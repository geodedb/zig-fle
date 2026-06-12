// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const hmac_mod = @import("../crypto/hmac.zig");

pub const BlindIndexToken = [32]u8;

/// Blind index for encrypted field equality search.
/// Maps HMAC(BIK, normalize(plaintext)) -> [record_ids]
pub const BlindIndex = struct {
    allocator: std.mem.Allocator,
    indices: std.StringHashMap(std.AutoHashMap(BlindIndexToken, std.ArrayList([]const u8))),

    pub fn init(allocator: std.mem.Allocator) BlindIndex {
        return .{
            .allocator = allocator,
            .indices = std.StringHashMap(std.AutoHashMap(BlindIndexToken, std.ArrayList([]const u8))).init(allocator),
        };
    }

    pub fn deinit(self: *BlindIndex) void {
        var it = self.indices.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);

            var token_map_it = entry.value_ptr.iterator();
            while (token_map_it.next()) |token_entry| {
                for (token_entry.value_ptr.items) |id| {
                    self.allocator.free(id);
                }
                token_entry.value_ptr.deinit(self.allocator);
            }
            entry.value_ptr.deinit();
        }
        self.indices.deinit();
    }

    fn buildFieldKey(allocator: std.mem.Allocator, schema: []const u8, field: []const u8) ![]u8 {
        const total = 4 + schema.len + 4 + field.len;
        const key = try allocator.alloc(u8, total);
        var pos: usize = 0;
        inline for (.{ schema, field }) |s| {
            std.mem.writeInt(u32, key[pos..][0..4], @intCast(s.len), .little);
            pos += 4;
            @memcpy(key[pos .. pos + s.len], s);
            pos += s.len;
        }
        return key;
    }

    /// Add or update blind index entry for a field value
    pub fn put(
        self: *BlindIndex,
        schema: []const u8,
        field: []const u8,
        bik: [32]u8,
        plaintext: []const u8,
        record_id: []const u8,
    ) !void {
        const field_key = try buildFieldKey(self.allocator, schema, field);
        defer self.allocator.free(field_key);

        const normalized = try hmac_mod.normalizeForBlindIndex(self.allocator, plaintext);
        defer {
            std.crypto.secureZero(u8, normalized);
            self.allocator.free(normalized);
        }

        var token: BlindIndexToken = undefined;
        hmac_mod.blindIndexHmac256(&token, &bik, normalized);

        // Allocate owned key before getOrPut to avoid dangling pointer on OOM.
        // Error handling is scoped: free owned_field_key only if getOrPut fails
        // (before ownership transfers). After getOrPut, the map or explicit free
        // handles lifetime — no errdefer needed.
        const owned_field_key = try self.allocator.dupe(u8, field_key);

        const gop = self.indices.getOrPut(field_key) catch |err| {
            self.allocator.free(owned_field_key);
            return err;
        };
        if (!gop.found_existing) {
            gop.key_ptr.* = owned_field_key;
            gop.value_ptr.* = std.AutoHashMap(BlindIndexToken, std.ArrayList([]const u8)).init(self.allocator);
        } else {
            self.allocator.free(owned_field_key);
        }

        var token_map = gop.value_ptr;

        const token_gop = try token_map.getOrPut(token);
        if (!token_gop.found_existing) {
            token_gop.value_ptr.* = std.ArrayList([]const u8).empty;
        }

        for (token_gop.value_ptr.items) |existing_id| {
            if (std.mem.eql(u8, existing_id, record_id)) {
                return;
            }
        }

        const owned_id = try self.allocator.dupe(u8, record_id);
        errdefer self.allocator.free(owned_id);
        try token_gop.value_ptr.append(self.allocator, owned_id);
    }

    /// Lookup record IDs matching a plaintext value.
    ///
    /// LIFETIME: the returned slice borrows index-internal storage and is
    /// valid only until the next mutating call (`put`, `remove`, `deinit`)
    /// on this BlindIndex. Callers that need to retain results must copy
    /// them before mutating the index.
    pub fn lookup(
        self: *BlindIndex,
        schema: []const u8,
        field: []const u8,
        bik: [32]u8,
        plaintext: []const u8,
    ) !?[]const []const u8 {
        const field_key = try buildFieldKey(self.allocator, schema, field);
        defer self.allocator.free(field_key);

        const token_map = self.indices.get(field_key) orelse return null;

        const normalized = try hmac_mod.normalizeForBlindIndex(self.allocator, plaintext);
        defer {
            std.crypto.secureZero(u8, normalized);
            self.allocator.free(normalized);
        }

        var token: BlindIndexToken = undefined;
        hmac_mod.blindIndexHmac256(&token, &bik, normalized);

        if (token_map.get(token)) |record_ids| {
            return record_ids.items;
        }

        return null;
    }

    /// Remove a record from all indices for a field
    pub fn remove(
        self: *BlindIndex,
        schema: []const u8,
        field: []const u8,
        record_id: []const u8,
    ) !void {
        const field_key = try buildFieldKey(self.allocator, schema, field);
        defer self.allocator.free(field_key);

        if (self.indices.getPtr(field_key)) |token_map| {
            var it = token_map.iterator();
            while (it.next()) |entry| {
                var i: usize = 0;
                while (i < entry.value_ptr.items.len) {
                    if (std.mem.eql(u8, entry.value_ptr.items[i], record_id)) {
                        const removed_id = entry.value_ptr.swapRemove(i);
                        self.allocator.free(removed_id);
                    } else {
                        i += 1;
                    }
                }
            }
        }
    }
};

test "BlindIndex put and lookup" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var index = BlindIndex.init(allocator);
    defer index.deinit();

    var bik: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&bik);

    try index.put("Person", "email", bik, "alice@example.com", "person1");
    try index.put("Person", "email", bik, "alice@example.com", "person2");
    try index.put("Person", "email", bik, "bob@example.com", "person3");

    const results = try index.lookup("Person", "email", bik, "alice@example.com");
    try testing.expect(results != null);
    try testing.expectEqual(@as(usize, 2), results.?.len);

    const results2 = try index.lookup("Person", "email", bik, "bob@example.com");
    try testing.expect(results2 != null);
    try testing.expectEqual(@as(usize, 1), results2.?.len);
    try testing.expectEqualStrings("person3", results2.?[0]);

    const results3 = try index.lookup("Person", "email", bik, "charlie@example.com");
    try testing.expect(results3 == null);
}

test "BlindIndex normalization handles case and whitespace" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var index = BlindIndex.init(allocator);
    defer index.deinit();

    var bik: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&bik);

    try index.put("Person", "email", bik, "  Alice@EXAMPLE.com  ", "person1");

    const results = try index.lookup("Person", "email", bik, "alice@example.com");
    try testing.expect(results != null);
    try testing.expectEqual(@as(usize, 1), results.?.len);
    try testing.expectEqualStrings("person1", results.?[0]);
}

test "BlindIndex field keys are injective across schema/field boundaries" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var index = BlindIndex.init(allocator);
    defer index.deinit();
    var bik: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&bik);

    try index.put("a.b", "c", bik, "v", "r1");
    // Different identity, same '.'-joined string under the old scheme.
    const results = try index.lookup("a", "b.c", bik, "v");
    try testing.expect(results == null);
}

test "BlindIndex remove" {
    const testing = std.testing;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var index = BlindIndex.init(allocator);
    defer index.deinit();

    var bik: [32]u8 = undefined;
    std.Io.Threaded.global_single_threaded.io().random(&bik);

    try index.put("Person", "email", bik, "alice@example.com", "person1");
    try index.put("Person", "email", bik, "alice@example.com", "person2");

    try index.remove("Person", "email", "person1");

    const results = try index.lookup("Person", "email", bik, "alice@example.com");
    try testing.expect(results != null);
    try testing.expectEqual(@as(usize, 1), results.?.len);
    try testing.expectEqualStrings("person2", results.?[0]);
}
