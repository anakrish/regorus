// Example RBAC Policies
const EXAMPLES = {
    simple: {
        name: "Simple Role Assignment",
        description: "Basic role assignment without conditions",
        policy: {
            version: "1.0",
            roleDefinitions: [{
                id: "StorageReader",
                name: "Storage Blob Data Reader",
                roleType: "CustomRole",
                assignableScopes: ["/subscriptions/sub1"],
                permissions: [{
                    actions: ["Microsoft.Storage/storageAccounts/read"],
                    dataActions: ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]
                }]
            }],
            roleAssignments: [{
                id: "assignment-1",
                principalId: "user-123",
                principalType: "User",
                roleDefinitionId: "StorageReader",
                scope: "/subscriptions/sub1/resourceGroups/rg1"
            }]
        },
        testCases: [
            {
                name: "Allow: User with assignment reads blob",
                expectedResult: true,
                context: {
                    principal: {
                        id: "user-123",
                        principalType: "User",
                        attributes: {}
                    },
                    resource: {
                        id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                        scope: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                        type: "Microsoft.Storage/storageAccounts",
                        attributes: {}
                    },
                    action: "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                    actionType: "dataAction",
                    request: {
                        attributes: {}
                    }
                }
            },
            {
                name: "Deny: Different user without assignment",
                expectedResult: false,
                context: {
                    principal: {
                        id: "user-999",
                        principalType: "User",
                        attributes: {}
                    },
                    resource: {
                        id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                        scope: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                        type: "Microsoft.Storage/storageAccounts",
                        attributes: {}
                    },
                    action: "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                    actionType: "dataAction",
                    request: {
                        attributes: {}
                    }
                }
            },
            {
                name: "Deny: User tries different action",
                expectedResult: false,
                context: {
                    principal: {
                        id: "user-123",
                        principalType: "User",
                        attributes: {}
                    },
                    resource: {
                        id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                        scope: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                        type: "Microsoft.Storage/storageAccounts",
                        attributes: {}
                    },
                    action: "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
                    actionType: "dataAction",
                    request: {
                        attributes: {}
                    }
                }
            }
        ]
    },

    conditional: {
        name: "Conditional Role Assignment",
        description: "Role assignment with condition on resource attribute",
        policy: {
            version: "1.0",
            roleDefinitions: [{
                id: "ConditionalReader",
                name: "Conditional Blob Reader",
                roleType: "CustomRole",
                assignableScopes: ["/subscriptions/sub1"],
                permissions: [{
                    actions: [],
                    dataActions: ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]
                }]
            }],
            roleAssignments: [{
                id: "assignment-2",
                principalId: "user-456",
                principalType: "User",
                roleDefinitionId: "ConditionalReader",
                scope: "/subscriptions/sub1",
                condition: "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringStartsWith 'public-'"
            }]
        },
        testCases: [
            {
                name: "Allow: Container name starts with 'public-'",
                expectedResult: true,
                context: {
                    principal: {
                        id: "user-456",
                        principalType: "User",
                        attributes: {}
                    },
                    resource: {
                        id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                        scope: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                        type: "Microsoft.Storage/storageAccounts",
                        attributes: {
                            "Microsoft.Storage/storageAccounts/blobServices/containers:name": "public-data"
                        }
                    },
                    action: "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                    actionType: "dataAction",
                    request: {
                        attributes: {}
                    }
                }
            },
            {
                name: "Deny: Container name doesn't start with 'public-'",
                expectedResult: false,
                context: {
                    principal: {
                        id: "user-456",
                        principalType: "User",
                        attributes: {}
                    },
                    resource: {
                        id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                        scope: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                        type: "Microsoft.Storage/storageAccounts",
                        attributes: {
                            "Microsoft.Storage/storageAccounts/blobServices/containers:name": "private-data"
                        }
                    },
                    action: "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                    actionType: "dataAction",
                    request: {
                        attributes: {}
                    }
                }
            },
            {
                name: "Deny: Different user",
                expectedResult: false,
                context: {
                    principal: {
                        id: "user-999",
                        principalType: "User",
                        attributes: {}
                    },
                    resource: {
                        id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                        scope: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                        type: "Microsoft.Storage/storageAccounts",
                        attributes: {
                            "Microsoft.Storage/storageAccounts/blobServices/containers:name": "public-data"
                        }
                    },
                    action: "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                    actionType: "dataAction",
                    request: {
                        attributes: {}
                    }
                }
            }
        ]
    },

    storage: {
        policy: {
            version: "1.0",
            roleDefinitions: [{
                id: "StorageDataReader",
                name: "Storage Blob Data Contributor",
                roleType: "CustomRole",
                assignableScopes: ["/subscriptions/sub1"],
                permissions: [{
                    actions: [],
                    dataActions: [
                        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"
                    ]
                }]
            }],
            roleAssignments: [{
                id: "assignment-3",
                principalId: "user-789",
                principalType: "User",
                roleDefinitionId: "StorageDataReader",
                scope: "/subscriptions/sub1/resourceGroups/rg1",
                condition: "(@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringStartsWith 'public-' || @Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path] StringStartsWith 'shared/') && @Request[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:encryptionScope] StringEquals 'default'"
            }]
        },
        context: {
            principal: {
                id: "user-789",
                principalType: "User",
                attributes: {}
            },
            resource: {
                id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                scope: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                type: "Microsoft.Storage/storageAccounts",
                attributes: {
                    "Microsoft.Storage/storageAccounts/blobServices/containers:name": "public-files",
                    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path": "shared/docs/file.txt"
                }
            },
            action: "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            actionType: "dataAction",
            request: {
                attributes: {
                    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs:encryptionScope": "default"
                }
            }
        }
    },

    time: {
        policy: {
            version: "1.0",
            roleDefinitions: [{
                id: "BusinessHoursReader",
                name: "Business Hours Reader",
                roleType: "CustomRole",
                assignableScopes: ["/subscriptions/sub1"],
                permissions: [{
                    actions: [],
                    dataActions: ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]
                }]
            }],
            roleAssignments: [{
                id: "assignment-4",
                principalId: "user-321",
                principalType: "User",
                roleDefinitionId: "BusinessHoursReader",
                scope: "/subscriptions/sub1",
                condition: "UtcNow() TimeOfDayGreaterThan 08:00 && UtcNow() TimeOfDayLessThan 18:00"
            }]
        },
        context: {
            principal: {
                id: "user-321",
                principalType: "User",
                attributes: {}
            },
            resource: {
                id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                scope: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                type: "Microsoft.Storage/storageAccounts",
                attributes: {}
            },
            action: "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            actionType: "dataAction",
            request: {
                attributes: {}
            }
        }
    },

    tags: {
        policy: {
            version: "1.0",
            roleDefinitions: [{
                id: "TagBasedReader",
                name: "Tag-Based Reader",
                roleType: "CustomRole",
                assignableScopes: ["/subscriptions/sub1"],
                permissions: [{
                    actions: [],
                    dataActions: ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]
                }]
            }],
            roleAssignments: [{
                id: "assignment-5",
                principalId: "user-555",
                principalType: "User",
                roleDefinitionId: "TagBasedReader",
                scope: "/subscriptions/sub1",
                condition: "@Principal[Microsoft.Directory/CustomSecurityAttributes/Id:Department] StringEquals @Resource[Microsoft.Storage/storageAccounts:tags:Department]"
            }]
        },
        context: {
            principal: {
                id: "user-555",
                principalType: "User",
                attributes: {
                    "Microsoft.Directory/CustomSecurityAttributes/Id:Department": "Engineering"
                }
            },
            resource: {
                id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                scope: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                type: "Microsoft.Storage/storageAccounts",
                attributes: {
                    "Microsoft.Storage/storageAccounts:tags:Department": "Engineering"
                }
            },
            action: "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            actionType: "dataAction",
            request: {
                attributes: {}
            }
        }
    },

    multi: {
        policy: {
            version: "1.0",
            roleDefinitions: [
                {
                    id: "Reader",
                    name: "Blob Reader",
                    roleType: "CustomRole",
                    assignableScopes: ["/subscriptions/sub1"],
                    permissions: [{
                        actions: [],
                        dataActions: ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]
                    }]
                },
                {
                    id: "Writer",
                    name: "Blob Writer",
                    roleType: "CustomRole",
                    assignableScopes: ["/subscriptions/sub1"],
                    permissions: [{
                        actions: [],
                        dataActions: [
                            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"
                        ]
                    }]
                }
            ],
            roleAssignments: [
                {
                    id: "assignment-6",
                    principalId: "user-999",
                    principalType: "User",
                    roleDefinitionId: "Reader",
                    scope: "/subscriptions/sub1"
                },
                {
                    id: "assignment-7",
                    principalId: "user-999",
                    principalType: "User",
                    roleDefinitionId: "Writer",
                    scope: "/subscriptions/sub1/resourceGroups/rg1",
                    condition: "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'temp-uploads' && UtcNow() TimeOfDayGreaterThan 06:00 && UtcNow() TimeOfDayLessThan 22:00"
                }
            ]
        },
        context: {
            principal: {
                id: "user-999",
                principalType: "User",
                attributes: {}
            },
            resource: {
                id: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                scope: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/storage1",
                type: "Microsoft.Storage/storageAccounts",
                attributes: {
                    "Microsoft.Storage/storageAccounts/blobServices/containers:name": "temp-uploads"
                }
            },
            action: "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
            actionType: "dataAction",
            request: {
                attributes: {}
            }
        }
    }
};

// Export for use in main app
if (typeof module !== 'undefined' && module.exports) {
    module.exports = EXAMPLES;
}
