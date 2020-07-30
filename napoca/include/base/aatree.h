/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef _AATREE_H_
#define _AATREE_H_

#include "core.h"

/** @file aatree.h
 *  @brief AATREE - Arne Anderson balanced binary tree interface
 *
 *  More informations on AATrees can be found at http://en.wikipedia.org/wiki/AA_tree.
 *  IMPORTANT: AA trees are NOT thread safe (do NOT use any synch primitives)
 */

#pragma pack(push)
#pragma pack(4)
/**
* @brief AATree internal node structure. Field ordering is critical!
*/
typedef struct _AANODE {
    struct _AANODE* Left;               ///< Left child of the current node
    struct _AANODE* Right;              ///< Right child of the current node
    struct _AANODE* Parent;             ///< Parent node of the current node
    QWORD           Key;                ///< Value of the node
    INT32           AaLevel;            ///< Level of the current node
    // statistics counters
    volatile INT32  SuccInsert;
    volatile INT32  FailedInsert;
    volatile INT32  SucclRemove;
    volatile INT32  FailedRemove;
    volatile INT32  SuccLookup;
    volatile INT32  FailedLookup;
} AANODE;
#pragma pack(pop)

typedef struct _AATREE AATREE;

/**
 * @brief Callback for freeing an AATree Node.
 *
 * @param[in]       Tree                                    Address of the AATree
 * @param[in,out]   Node                                    Address of the AATree Node to be freed
 */
typedef NTSTATUS (*PFUNC_FreeAaNode)(
    _In_ AATREE* Tree,
    _Inout_ AANODE **Node
    );

/**
 * @brief   Actual AATree structure, contains the root. Field ordering is critical!
*/
typedef struct _AATREE {
    AANODE*             Root;           ///< Root of the AATree
    volatile INT32      NodeCount;      ///< Tree node count
    PFUNC_FreeAaNode    FreeNode;       ///< Callback for freeing the AATree's nodes
} AATREE;

/**
 * @brief   Preinitialize a given AATree.
 *
 * Sets the tree root to NULL and node count to 0.
 *
 * @param[in]   Tree                                        Address of the AATree to be preinitialized
 */
void
AaPreinit(
    _In_ AATREE* Tree
    );

/**
 * @brief   Setup the given tree's FreeNode callback method.
 *
 * @param[in]   Tree                                        The AATree structure to be initialized
 * @param[in]   FreeNodeCallback                            The tree's callback for freeing nodes
 *
 * @return CX_STATUS_SUCCESS                                Initialization was successful
 * @return CX_STATUS_INVALID_PARAMETER_1                    Tree is null
 * @return CX_STATUS_INVALID_PARAMETER_2                    FreeNodeCallback is null
 */
NTSTATUS
AaInit(
    _In_ AATREE* Tree,
    _In_ PFUNC_FreeAaNode FreeNodeCallback
    );

/**
 * @brief   Uninitialize the given AATree structure by calling the FreeNode callback on every node of the tree.
 *
 * @param[in]   Tree                                        The AATree structure to be uninitialized
 *
 * @return CX_STATUS_SUCCESS                                Uninitialization was successful
 * @return CX_STATUS_INVALID_PARAMETER_1                    Tree is null
 * @return CX_STATUS_INCONSISTENT_DATA_VALUE                If the tree has an inconsistent structure
 * @return OTHER                                            FreeNode callback error
 */
NTSTATUS
AaUninit(
    _In_ AATREE* Tree
    );

/**
 * @brief   Insert a node in the AATree and performs a rebalance operation.
 *
 * @param[in]   Tree                                        The AATree structure to be inserted into
 * @param[in]   Node                                        The Node to be inserted
 *
 * @return CX_STATUS_SUCCESS                                Insertion was successful
 * @return CX_STATUS_INVALID_PARAMETER_1                    Tree is null
 * @return CX_STATUS_INVALID_PARAMETER_2                    Node is null
 * @return STATUS_DUPLICATE_KEY                             If the node key already exists in the tree
 * @return OTHER                                            Internal error
 */
NTSTATUS
AaInsert(
    _In_ AATREE* Tree,
    _In_ AANODE* Node
    );

/**
 * @brief   Searche the AATree for a given key and, if found, returns the node.
 *
 * @param[in]    Tree                                       The AATree to be searched
 * @param[in]    Key                                        The key to be searched
 * @param[out]   Node                                       If return status is CX_STATUS_SUCCESS, contains the node with the searched key
 *
 * @return CX_STATUS_SUCCESS                                Search was successful, the key was found
 * @return CX_STATUS_INVALID_PARAMETER_1                    The Tree is null
 * @return CX_STATUS_INVALID_PARAMETER_3                    The Node is null
 * @return CX_STATUS_DATA_NOT_FOUND                         No node with the given key is present in the tree
 */
NTSTATUS
AaLookup(
    _In_ AATREE* Tree,
    _In_ QWORD Key,
    _Out_ AANODE **Node
    );

/**
 * @brief   Remove a node from the tree and rebalances it.
 *
 * @param[in]    Tree                                       The AATree to be deleted from
 * @param[in]    Node                                       The node to delete
 * @param[out]   Successor                                  The successor of the deleted node
 *
 * @return CX_STATUS_SUCCESS                                Node was successfully removed
 * @return CX_STATUS_INVALID_PARAMETER_1                    Tree is null
 * @return CX_STATUS_INVALID_PARAMETER_2                    Node is null
 * @return CX_STATUS_INCONSISTENT_DATA_VALUE                If the tree has an inconsistent structure
 * @return OTHER                                            Internal error
 */
NTSTATUS
AaRemove(
    _In_ AATREE* Tree,
    _In_ AANODE* Node,
    _In_opt_ AANODE* Successor
    );

/**
 * @brief   Check the integrity of an AATree.
 *
 * @param[in]   Tree                                        The AATree to be checked
 *
 * @return CX_STATUS_SUCCESS                                The tree passed the integrity check
 * @return CX_STATUS_INVALID_PARAMETER_1                    The Tree is null
 * @return CX_STATUS_INCONSISTENT_DATA_VALUE                If the tree has an inconsistent structure
 */
NTSTATUS
AaCheckIntegrity(
    _In_ AATREE* Tree
    );

/**
 * @brief   Dump an AATree structure.
 *
 * @param[in]   Tree                                        The AATree to be dumped
 *
 * @return CX_STATUS_SUCCESS                                Dump was successful
 * @return CX_STATUS_INVALID_PARAMETER_1                    Tree is null
 * @return OTHER                                            Internal error
 */
NTSTATUS
AaDump(
    _In_ AATREE* Tree
    );

#endif // _AATREE_H_