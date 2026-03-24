// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

/// Key identifiers for hierarchical key management
pub const KeyIds = struct {
    tenant: []const u8,
    schema: []const u8,
    field: []const u8,
    version: u16,
};
