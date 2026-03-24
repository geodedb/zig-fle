// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

/// Field encryption configuration
pub const EncryptionConfig = struct {
    enabled: bool = false,
    algorithm: Algorithm = .aes256_gcm,
    key_scope: KeyScope = .field,
    rotation_interval_days: ?u32 = null,

    pub const Algorithm = enum {
        aes256_gcm,
        chacha20_poly1305,

        pub fn fromString(s: []const u8) !Algorithm {
            if (std.ascii.eqlIgnoreCase(s, "AES-256-GCM")) return .aes256_gcm;
            if (std.ascii.eqlIgnoreCase(s, "CHACHA20-POLY1305")) return .chacha20_poly1305;
            return error.InvalidAlgorithm;
        }
    };

    pub const KeyScope = enum {
        field,
        schema,

        pub fn fromString(s: []const u8) !KeyScope {
            if (std.ascii.eqlIgnoreCase(s, "field")) return .field;
            if (std.ascii.eqlIgnoreCase(s, "schema")) return .schema;
            return error.InvalidKeyScope;
        }
    };
};

/// Field searchability configuration
pub const SearchConfig = struct {
    enabled: bool = false,
    index_type: IndexType = .blind_hmac_sha256,

    pub const IndexType = enum {
        blind_hmac_sha256,

        pub fn fromString(s: []const u8) !IndexType {
            if (std.ascii.eqlIgnoreCase(s, "blind-hmac-sha256")) return .blind_hmac_sha256;
            return error.InvalidIndexType;
        }
    };
};

/// Field visibility configuration (RBAC)
pub const VisibilityConfig = struct {
    to_roles: [][]const u8 = &.{},
};

/// Field classification tags
pub const ClassificationConfig = struct {
    tags: [][]const u8 = &.{},
};

/// Complete field metadata from annotations
pub const FieldMetadata = struct {
    field_name: []const u8,
    encryption: EncryptionConfig = .{},
    search: SearchConfig = .{},
    visibility: VisibilityConfig = .{},
    classification: ClassificationConfig = .{},

    pub fn isEncrypted(self: *const FieldMetadata) bool {
        return self.encryption.enabled;
    }

    pub fn isSearchable(self: *const FieldMetadata) bool {
        return self.search.enabled;
    }

    pub fn algorithm(self: *const FieldMetadata) ?EncryptionConfig.Algorithm {
        if (!self.encryption.enabled) return null;
        return self.encryption.algorithm;
    }
};

/// Schema catalog entry for a type
pub const TypeMetadata = struct {
    type_name: []const u8,
    fields: std.StringHashMap(FieldMetadata),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, type_name: []const u8) TypeMetadata {
        return .{
            .type_name = type_name,
            .fields = std.StringHashMap(FieldMetadata).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TypeMetadata) void {
        // Free heap-allocated annotation slices owned by FieldMetadata values
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            const meta = entry.value_ptr;
            if (meta.visibility.to_roles.len > 0) {
                self.allocator.free(meta.visibility.to_roles);
            }
            if (meta.classification.tags.len > 0) {
                self.allocator.free(meta.classification.tags);
            }
        }
        self.fields.deinit();
    }

    pub fn getField(self: *const TypeMetadata, field_name: []const u8) ?FieldMetadata {
        return self.fields.get(field_name);
    }

    pub fn isFieldEncrypted(self: *const TypeMetadata, field_name: []const u8) bool {
        if (self.getField(field_name)) |meta| {
            return meta.isEncrypted();
        }
        return false;
    }

    pub fn isFieldSearchable(self: *const TypeMetadata, field_name: []const u8) bool {
        if (self.getField(field_name)) |meta| {
            return meta.isSearchable();
        }
        return false;
    }
};

/// Annotation parser for FLE schema extensions.
/// Parses: @encrypted(alg:"AES-256-GCM", key_scope:"field", rotate:"90d")
///         @searchable(index:"blind-hmac-sha256")
///         @visible(to_roles:["role1","role2"])
///         @classify(tags:["PII","Restricted"])
pub const AnnotationParser = struct {
    source: []const u8,
    pos: usize = 0,

    pub fn init(source: []const u8) AnnotationParser {
        return .{ .source = source };
    }

    fn peek(self: *AnnotationParser) ?u8 {
        if (self.pos >= self.source.len) return null;
        return self.source[self.pos];
    }

    fn advance(self: *AnnotationParser) void {
        if (self.pos < self.source.len) self.pos += 1;
    }

    fn skipWhitespace(self: *AnnotationParser) void {
        while (self.peek()) |ch| {
            if (!std.ascii.isWhitespace(ch)) break;
            self.advance();
        }
    }

    fn consumeChar(self: *AnnotationParser, expected: u8) bool {
        if (self.peek() == expected) {
            self.advance();
            return true;
        }
        return false;
    }

    fn parseIdentifier(self: *AnnotationParser) ![]const u8 {
        self.skipWhitespace();
        const start = self.pos;
        while (self.peek()) |ch| {
            if (std.ascii.isAlphanumeric(ch) or ch == '_') {
                self.advance();
            } else {
                break;
            }
        }
        if (self.pos == start) return error.ExpectedIdentifier;
        return self.source[start..self.pos];
    }

    fn parseString(self: *AnnotationParser) ![]const u8 {
        self.skipWhitespace();
        if (!self.consumeChar('"')) return error.ExpectedString;
        const start = self.pos;
        while (self.peek()) |ch| {
            if (ch == '"') break;
            self.advance();
        }
        const end = self.pos;
        if (!self.consumeChar('"')) return error.UnterminatedString;
        return self.source[start..end];
    }

    fn parseArray(self: *AnnotationParser, allocator: std.mem.Allocator) ![][]const u8 {
        self.skipWhitespace();
        if (!self.consumeChar('[')) return error.ExpectedArray;

        var temp_items: [16][]const u8 = undefined;
        var count: usize = 0;

        while (count < 16) {
            self.skipWhitespace();
            if (self.consumeChar(']')) break;

            const item = try self.parseString();
            temp_items[count] = item;
            count += 1;

            self.skipWhitespace();
            if (!self.consumeChar(',')) {
                self.skipWhitespace();
                if (!self.consumeChar(']')) return error.ExpectedCommaOrBracket;
                break;
            }
        }

        const result = try allocator.alloc([]const u8, count);
        @memcpy(result, temp_items[0..count]);
        return result;
    }

    /// Parse a single annotation.
    /// Returns annotation name, string params, and array params.
    pub fn parseAnnotation(self: *AnnotationParser, allocator: std.mem.Allocator) !?struct {
        name: []const u8,
        params: std.StringHashMap([]const u8),
        arrays: std.StringHashMap([][]const u8),
    } {
        self.skipWhitespace();
        if (!self.consumeChar('@')) return null;

        const name = try self.parseIdentifier();

        var params = std.StringHashMap([]const u8).init(allocator);
        var arrays = std.StringHashMap([][]const u8).init(allocator);

        self.skipWhitespace();
        if (self.consumeChar('(')) {
            while (true) {
                self.skipWhitespace();
                if (self.consumeChar(')')) break;

                const param_name = try self.parseIdentifier();
                self.skipWhitespace();
                if (!self.consumeChar(':')) return error.ExpectedColon;

                self.skipWhitespace();
                if (self.peek() == '[') {
                    const arr = try self.parseArray(allocator);
                    try arrays.put(param_name, arr);
                } else {
                    const value = try self.parseString();
                    try params.put(param_name, value);
                }

                self.skipWhitespace();
                if (!self.consumeChar(',')) {
                    self.skipWhitespace();
                    if (!self.consumeChar(')')) return error.ExpectedCommaOrParen;
                    break;
                }
            }
        }

        return .{ .name = name, .params = params, .arrays = arrays };
    }
};

/// Apply annotations to a field and update metadata
pub fn applyAnnotations(
    allocator: std.mem.Allocator,
    type_meta: *TypeMetadata,
    field_name: []const u8,
    annotations_text: []const u8,
) !void {
    var field_meta = FieldMetadata{ .field_name = field_name };
    var parser = AnnotationParser.init(annotations_text);

    while (try parser.parseAnnotation(allocator)) |annot| {
        var annotation = annot;
        defer annotation.params.deinit();
        defer {
            var it = annotation.arrays.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.value_ptr.*);
            }
            annotation.arrays.deinit();
        }

        if (std.ascii.eqlIgnoreCase(annotation.name, "encrypted")) {
            field_meta.encryption.enabled = true;

            if (annotation.params.get("alg")) |alg| {
                field_meta.encryption.algorithm = try EncryptionConfig.Algorithm.fromString(alg);
            }

            if (annotation.params.get("key_scope")) |scope| {
                field_meta.encryption.key_scope = try EncryptionConfig.KeyScope.fromString(scope);
            }

            if (annotation.params.get("rotate")) |rotate_str| {
                if (rotate_str.len > 1 and rotate_str[rotate_str.len - 1] == 'd') {
                    const days_str = rotate_str[0 .. rotate_str.len - 1];
                    field_meta.encryption.rotation_interval_days = try std.fmt.parseInt(u32, days_str, 10);
                }
            }
        } else if (std.ascii.eqlIgnoreCase(annotation.name, "searchable")) {
            field_meta.search.enabled = true;

            if (annotation.params.get("index")) |index_type| {
                field_meta.search.index_type = try SearchConfig.IndexType.fromString(index_type);
            }
        } else if (std.ascii.eqlIgnoreCase(annotation.name, "visible")) {
            if (annotation.arrays.get("to_roles")) |roles| {
                field_meta.visibility.to_roles = try allocator.dupe([]const u8, roles);
            }
        } else if (std.ascii.eqlIgnoreCase(annotation.name, "classify")) {
            if (annotation.arrays.get("tags")) |tags| {
                field_meta.classification.tags = try allocator.dupe([]const u8, tags);
            }
        }
    }

    try type_meta.fields.put(field_name, field_meta);
}

test "Parse @encrypted annotation" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const text = "@encrypted(alg:\"AES-256-GCM\", key_scope:\"field\", rotate:\"90d\")";
    var parser = AnnotationParser.init(text);

    var annotation = (try parser.parseAnnotation(allocator)).?;
    defer annotation.params.deinit();
    defer annotation.arrays.deinit();

    try testing.expectEqualStrings("encrypted", annotation.name);
    try testing.expectEqualStrings("AES-256-GCM", annotation.params.get("alg").?);
    try testing.expectEqualStrings("field", annotation.params.get("key_scope").?);
    try testing.expectEqualStrings("90d", annotation.params.get("rotate").?);
}

test "Parse @searchable annotation" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const text = "@searchable(index:\"blind-hmac-sha256\")";
    var parser = AnnotationParser.init(text);

    var annotation = (try parser.parseAnnotation(allocator)).?;
    defer annotation.params.deinit();
    defer annotation.arrays.deinit();

    try testing.expectEqualStrings("searchable", annotation.name);
    try testing.expectEqualStrings("blind-hmac-sha256", annotation.params.get("index").?);
}

test "Parse @visible annotation with array" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const text = "@visible(to_roles:[\"pii_reader\",\"admin\"])";
    var parser = AnnotationParser.init(text);

    var annotation = (try parser.parseAnnotation(allocator)).?;
    defer annotation.params.deinit();
    defer {
        var it = annotation.arrays.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.value_ptr.*);
        }
        annotation.arrays.deinit();
    }

    try testing.expectEqualStrings("visible", annotation.name);
    const roles = annotation.arrays.get("to_roles").?;
    try testing.expectEqual(@as(usize, 2), roles.len);
    try testing.expectEqualStrings("pii_reader", roles[0]);
    try testing.expectEqualStrings("admin", roles[1]);
}

test "Apply annotations to field metadata" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var type_meta = TypeMetadata.init(allocator, "Person");
    defer type_meta.deinit();

    const annotations = "@encrypted(alg:\"AES-256-GCM\") @searchable(index:\"blind-hmac-sha256\")";
    try applyAnnotations(allocator, &type_meta, "ssn", annotations);

    const field_meta = type_meta.getField("ssn").?;
    try testing.expect(field_meta.isEncrypted());
    try testing.expect(field_meta.isSearchable());
    try testing.expectEqual(EncryptionConfig.Algorithm.aes256_gcm, field_meta.algorithm().?);
}
