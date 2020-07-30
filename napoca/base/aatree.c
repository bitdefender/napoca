/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

#include "napoca.h"
#include "wrappers/crt_short/stdlib.h"
#include "base/aatree.h"
#include "memory/heap.h"

/** @file aatree.c
 * @brief AATREE - Arne Anderson balanced binary tree implementation
 *
 * An AATree is a balanced binary tree, much like a red black tree structure. It consists of two balancing operations, skew and split.
 * For more informations about AATrees: https://en.wikipedia.org/wiki/AA_tree.
 * The current implementation does not support same key nodes insertions.
 */

#define MAX_AATREE_DEPTH    40  ///< Max tree depth supported

//
// local prototypes
//
static
NTSTATUS
_AaSkew(
    _In_ AATREE* Tree,
    _Inout_ AANODE **Node
    );

static
NTSTATUS
_AaSplit(
    _In_ AATREE* Tree,
    _Inout_ AANODE **Node
    );

static
NTSTATUS
_AaRebalanceAllAfterInsert(
    _In_ AATREE* Tree,
    _In_ AANODE* StartNode
    );

static
NTSTATUS
_AaRebalanceAllAfterRemove(
    _In_ AATREE* Tree,
    _In_ AANODE* StartNode
    );

static
NTSTATUS
_AaDump2(
    _In_ AANODE* Node,
    _In_ DWORD Level
    );

static
NTSTATUS
_AaCheckIntegrityByNode(
    _In_ AANODE* Node,
    _Out_ DWORD *SubtreeNodeCount
    );


void
AaPreinit(
    _In_ AATREE* Tree
    )
{
    assert(Tree != NULL);

    Tree->Root = NULL;
    Tree->NodeCount = 0;
}


NTSTATUS
AaInit(
    _In_ AATREE* Tree,
    _In_ PFUNC_FreeAaNode FreeNodeCallback
    )
{
    if (Tree == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (FreeNodeCallback == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    // setup callbacks (nothing more to do here)
    Tree->FreeNode = FreeNodeCallback;

    return CX_STATUS_SUCCESS;
}


NTSTATUS
AaUninit(
    _In_ AATREE* Tree
    )
{
    NTSTATUS status;
    AANODE* stack[MAX_AATREE_DEPTH];
    INT32 level;
    AANODE* node;

    level = -1;

    if (Tree == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (Tree->Root != NULL)
    {
        level = 0;
        stack[0] = Tree->Root;
    }

    // remove all nodes, depth-first
    while (level >= 0)
    {
        node = stack[level];

        if (node->Left != NULL)
        {
            level++;
            stack[level] = node->Left;
            continue;
        }

        if (node->Right != NULL)
        {
            level++;
            stack[level] = node->Right;
            continue;
        }

        // this is a leaf - first of all, remove the node from the tree (unlink)
        if (node->Parent != NULL)
        {
            if (node->Parent->Left == node) node->Parent->Left = NULL;
            else if (node->Parent->Right == node) node->Parent->Right = NULL;
            else
            {
                // integrity violation
                ERROR("inconsistency, child-to-parent ptr points to invalid parent\n");
                status = CX_STATUS_INCONSISTENT_DATA_VALUE;
                goto cleanup;
            }
        }
        else
        {
            // this must be the root
            Tree->Root = NULL;
        }

        Tree->NodeCount--;

        // secondly, free the node
        status = Tree->FreeNode(Tree, &node);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("FreeNode", status);
            goto cleanup;
        }

        // then finally, pop the stack
        stack[level] = NULL;
        level--;
    }

    // some integrity checks
    if (Tree->Root != NULL)
    {
        ERROR("inconsistency, tree with non-null root after all nodes are removed\n");
        status = CX_STATUS_INCONSISTENT_DATA_VALUE;
        goto cleanup;
    }

    if (Tree->NodeCount != 0)
    {
        ERROR("inconsistency, tree with non-zero node count after all nodes are removed\n");
        status = CX_STATUS_INCONSISTENT_DATA_VALUE;
        goto cleanup;
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

/**
 * @brief   Rebalancing operation. A right rotation for handling a left horizontal link.
 *
 * @param[in]       Tree                                    The AATree to be checked
 * @param[in,out]   Node                                    The candidate Node to be skewed
 *
 * @return CX_STATUS_SUCCESS                                The node was successfully skewed
 * @return CX_STATUS_INVALID_PARAMETER_1                    The Tree is null
 * @return CX_STATUS_INVALID_PARAMETER_2                    The Node is null
 * @return CX_STATUS_NOT_NEEDED_HINT                        This node does not require skewing
 * @return CX_STATUS_INCONSISTENT_DATA_VALUE                The tree has an inconsistent structure
 */
static
NTSTATUS
_AaSkew(
    _In_ AATREE* Tree,
    _Inout_ AANODE **Node
    )
{
    NTSTATUS status;
    AANODE *t, *p, *l, *r, *a, *b;

    if (Tree == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if ((Node == NULL) || (*Node == NULL)) return CX_STATUS_INVALID_PARAMETER_2;

    // see http://en.wikipedia.org/wiki/AA_tree for notations
    t = *Node;
    p = t->Parent;
    l = t->Left;
    r = t->Right;
    if (l != NULL)
    {
        a = l->Left;
        b = l->Right;
    }
    else
    {
        a = NULL;
        b = NULL;
    }

    // do we need to skew?
    if ((l == NULL) || (l->AaLevel < t->AaLevel)) return CX_STATUS_NOT_NEEDED_HINT;

    // set movements
    if (p != NULL)
    {
        l->Parent = p;
        if (t == p->Left) p->Left = l;
        else if (t == p->Right) p->Right = l;
        else
        {
            // inconsistency, shall never be the case
            ERROR("node is not the left nor the right child of parent\n");
            status = CX_STATUS_INCONSISTENT_DATA_VALUE;
            goto cleanup;
        }
    }
    else
    {
        // special case, T was the root of the tree
        l->Parent = NULL;
        Tree->Root = l;
    }

    t->Parent = l;
    l->Right = t;

    if (b != NULL) b->Parent = t;
    t->Left = b;

    // set return pointer
    *Node = l;

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

/**
 * @brief   Rebalancing operation. A left rotation for diminishing the number of right horizontal links of a node.
 *
 * @param[in]       Tree                                    The AATree to be checked
 * @param[in,out]   Node                                    The candidate Node to be split
 *
 * @return CX_STATUS_SUCCESS                                The node was successfully split
 * @return CX_STATUS_INVALID_PARAMETER_1                    The Tree is null
 * @return CX_STATUS_INVALID_PARAMETER_2                    The Node is null
 * @return CX_STATUS_NOT_NEEDED_HINT                        This node does not require splitting
 * @return CX_STATUS_INCONSISTENT_DATA_VALUE                The tree has an inconsistent structure
 */
static
NTSTATUS
_AaSplit(
    _In_ AATREE* Tree,
    _Inout_ AANODE **Node
    )
{
    NTSTATUS status;
    AANODE *t, *p, *r, *a, *b, *x;

    if (Tree == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if ((Node == NULL) || (*Node == NULL)) return CX_STATUS_INVALID_PARAMETER_2;

    // see http://en.wikipedia.org/wiki/AA_tree for notations
    t = *Node;
    p = t->Parent;
    a = t->Left;
    r = t->Right;
    if (r != NULL)
    {
        b = r->Left;
        x = r->Right;
    }
    else
    {
        b = NULL;
        x = NULL;
    }

    // do we need to split?
    if (((r == NULL) || (r->AaLevel <= t->AaLevel)) &&      // needed for after-decrease-level-of-left-child adjustments on remove
        ((x == NULL) || (x->AaLevel < t->AaLevel)))         // needed for after-insert adjustments
    {
        return CX_STATUS_NOT_NEEDED_HINT;
    }

    // set movements
    if (p != NULL)
    {
        r->Parent = p;
        if (t == p->Left) p->Left = r;
        else if (t == p->Right) p->Right = r;
        else
        {
            // inconsistency, shall never be the case
            ERROR("node %p is not the left nor the right child of parent %p\n", t, p);
            status = CX_STATUS_INCONSISTENT_DATA_VALUE;
            goto cleanup;
        }
    }
    else
    {
        // special case, T was the root of the tree
        r->Parent = NULL;
        Tree->Root = r;
    }

    t->Parent = r;          // #3
    r->Left = t;            // #4

    if (b != NULL) b->Parent = t;      // #5
    t->Right = b;           // #6

    // adjust AA level of r
    r->AaLevel = t->AaLevel + 1;

    // set return pointer
    *Node = r;

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

/**
 * @brief   Iterates the tree upwards starting from StartNode
 * @brief   and applies skew/split operations where required in order to rebalance the tree after an insert operation.
 *
 * @param[in] Tree                                          The AATree to be checked
 * @param[in] StartNode                                     The starting node of the rebalancing process
 *
 * @return CX_STATUS_SUCCESS                                The node was successfully rebalanced
 * @return CX_STATUS_INVALID_PARAMETER_1                    The Tree is null
 * @return CX_STATUS_INVALID_PARAMETER_2                    The Node is null
 * @return OTHER                                            Internal error
 */
static
NTSTATUS
_AaRebalanceAllAfterInsert(
    _In_ AATREE* Tree,
    _In_ AANODE* StartNode
    )
{
    NTSTATUS status;
    AANODE* node;
    INT32 fixes;

    if (Tree == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (StartNode == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    node = StartNode;
    fixes = 2;          // we stop if we don't SKEW or SPLIT after two levels upward

    while ((node != NULL) && (fixes > 0))
    {
        BOOLEAN opDone;

        opDone = FALSE;

        // first of all SKEW
        status = _AaSkew(Tree, &node);
        if (!SUCCESS(status)) goto cleanup;
        if (status != CX_STATUS_NOT_NEEDED_HINT) opDone = TRUE;

        // in the next step SPLIT
        status = _AaSplit(Tree, &node);
        if (!SUCCESS(status)) goto cleanup;
        if (status != CX_STATUS_NOT_NEEDED_HINT) opDone = TRUE;

        if (opDone) fixes = 2;
        else fixes--; // after two consecutive iteration this can reach 0, at which point we can stop updating stuff

        // go to upper node
        node = node->Parent;
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

/**
 * @brief   Iterates the tree downwards starting from StartNode
 * @brief   and applies skew/split operations where required in order to rebalance the tree after a remove operation.
 *
 * @param[in] Tree                                          The AATree to be checked
 * @param[in] StartNode                                     The starting node of the rebalancing process
 *
 * @return CX_STATUS_SUCCESS                                The node was successfully rebalanced
 * @return CX_STATUS_INVALID_PARAMETER_1                    The Tree is null
 * @return CX_STATUS_INVALID_PARAMETER_2                    The Node is null
 * @return OTHER                                            Internal error
 */
static
NTSTATUS
_AaRebalanceAllAfterRemove(
    _In_ AATREE* Tree,
    _In_ AANODE* StartNode
    )
{
    NTSTATUS status;
    AANODE* node;
    INT32 fixes;

    if (Tree == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (StartNode == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    node = StartNode;
    fixes = 2;          // we stop if we don't DECREASE-LEVEL, SKEW or SPLIT after three levels upward

    while ((node != NULL) && (fixes > 0))
    {
        INT32 leftLevel, rightLevel, thisLevel;
        AANODE* x;
        BOOLEAN opDone;

        opDone = FALSE;

        // first of all, decrease levels if needed (only after remove operations)
        leftLevel = (node->Left != NULL) ? (node->Left->AaLevel) : 0;
        rightLevel = (node->Right != NULL) ? (node->Right->AaLevel) : 0;
        thisLevel = MIN(leftLevel, rightLevel) + 1;

        if (node->AaLevel != thisLevel)
        {
            node->AaLevel = thisLevel;
            opDone = TRUE;
        }

        // skew this node
        status = _AaSkew(Tree, &node);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("_AaSkew", status);
            goto cleanup;
        }
        if (status != CX_STATUS_NOT_NEEDED_HINT) opDone = TRUE;

        // skew node->Right
        x = node->Right;
        if (x != NULL)
        {
            status = _AaSkew(Tree, &x);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("_AaSkew", status);
                goto cleanup;
            }
            if (status != CX_STATUS_NOT_NEEDED_HINT) opDone = TRUE;

            // skew node->Right->Right
            x = node->Right->Right;
            if (x != NULL)
            {
                status = _AaSkew(Tree, &x);
                if (!SUCCESS(status))
                {
                    LOG_FUNC_FAIL("_AaSkew", status);
                    goto cleanup;
                }
                if (status != CX_STATUS_NOT_NEEDED_HINT) opDone = TRUE;
            }
        }

        // split this node
        status = _AaSplit(Tree, &node);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("_AaSplit", status);
            goto cleanup;
        }
        if (status != CX_STATUS_NOT_NEEDED_HINT) opDone = TRUE;

        // split node->Left
        x = node->Left;
        if (x != NULL)
        {
            status = _AaSplit(Tree, &x);
            if (!SUCCESS(status))
            {
                LOG_FUNC_FAIL("_AaSplit", status);
                goto cleanup;
            }
            if (status != CX_STATUS_NOT_NEEDED_HINT) opDone = TRUE;
        }

        if (opDone) fixes = 2;
        else
        {
            // after two consecutive iteration this can reach 0, at which point we can stop updating stuff
            fixes--;

            // go to upper node
            node = node->Parent;
        }
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}


NTSTATUS
AaInsert(
    _In_ AATREE* Tree,
    _In_ AANODE* Node
    )
{
    NTSTATUS status;
    AANODE *parent, *n;
    AANODE **toChildPtr;

    toChildPtr = NULL;

    if (Tree == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (Node == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    // lookup place where we shall insert
    n = Tree->Root;
    parent = NULL;

    while (n != NULL)
    {
        if (Node->Key == n->Key)
        {
            status = STATUS_DUPLICATE_KEY;
            goto cleanup;
        }
        else if (Node->Key < n->Key)
        {
            parent = n;
            toChildPtr = &(n->Left);
            n = n->Left;
        }
        else // (Node->Key > n->Key)
        {
            parent = n;
            toChildPtr = &(n->Right);
            n = n->Right;
        }
    }

    // perform insertion
    if (parent != NULL)
    {
        // insert item below parent
        Tree->NodeCount++;
        *toChildPtr = Node;
        Node->Parent = parent;
        Node->Left = NULL;
        Node->Right = NULL;
        Node->AaLevel = 1;

        // rebalance upwards (repeatedly skew-then-split if needed)
        status = _AaRebalanceAllAfterInsert(Tree, parent);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("_AaRebalanceAllAfterInsert", status);
            goto cleanup;
        }
    }
    else
    {
        // special case, we insert the first node into the tree
        Tree->Root = Node;
        Tree->NodeCount++;
        Node->Parent = NULL;
        Node->Left = NULL;
        Node->Right = NULL;
        Node->AaLevel = 1;
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}


NTSTATUS
AaLookup(
    _In_ AATREE* Tree,
    _In_ QWORD Key,
    _Out_ AANODE **Node
    )
{
    AANODE* node;

    if (Tree == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (Node == NULL) return CX_STATUS_INVALID_PARAMETER_3;

    *Node = NULL;

    node = Tree->Root;
    while (node != NULL)
    {
        if (Key == node->Key) break;

        if (Key < node->Key) node = node->Left;
        else node = node->Right;
    }

    if (node == NULL) return CX_STATUS_DATA_NOT_FOUND;

    *Node = node;

    return CX_STATUS_SUCCESS;
}


NTSTATUS
AaRemove(
    _In_ AATREE* Tree,
    _In_ AANODE* Node,
    _In_opt_ AANODE* Successor
    )
{
    NTSTATUS status;
    AANODE *p, *t, *a, *b, *c, *d, *q, *s;
    AANODE **toChildPtr;
    INT32 tmpLevel;

    if (Tree == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (Node == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    // get node to delete
    t = Node;
    p = t->Parent;
    if (p != NULL)
    {
        if (t == p->Left) toChildPtr = &p->Left;
        else if (t == p->Right) toChildPtr = &p->Right;
        else
        {
            ERROR("inconsistency, node is not the left neither the right child of it's parent\n");
            status = CX_STATUS_INCONSISTENT_DATA_VALUE;
            goto cleanup;
        }
    }
    else toChildPtr = NULL;
    a = t->Left;
    b = t->Right;

    // handle complex case: when t is NOT a leaf node
    if ((a != NULL) && (b != NULL))
    {
        // find successor node into s, with q as it's parent
        if (Successor != NULL)
        {
            // optimization (in some cases we already know in O(1) complexity the successor element)
            s = Successor;
            q = s->Parent;
            if (q == t) q = NULL;
        }
        else
        {
            q = NULL;
            s = t->Right;
            while (s->Left != NULL)
            {
                q = s;
                s = s->Left;
            }
        }

        // now we can have two subcases
        if (s == t->Right)
        {
            // s is immediate right child of t
            b = NULL;
            c = s->Right;
            d = NULL;
            q = NULL;

            // make switch
            s->Parent = p;          // #1
            if (p != NULL) *toChildPtr = s;    // #2
            else Tree->Root = s;

            a->Parent = s;          // #3
            s->Left = a;            // #4

            t->Parent = s;          // #5
            s->Right = t;           // #6

            if (c != NULL) c->Parent = t;
            t->Right = c;           // #8
            t->Left = NULL;         // #9

            tmpLevel = s->AaLevel;
            s->AaLevel = t->AaLevel;
            t->AaLevel = tmpLevel;
        }
        else
        {
            // s is left child of b  (note that b might be equal to q)
            c = s->Right;
            d = q->Right;

            // make switch
            s->Parent = p;
            if (p != NULL) *toChildPtr = s;
            else Tree->Root = s;

            a->Parent = s;
            s->Left = a;

            b->Parent = s;
            s->Right = b;

            t->Parent = q;
            q->Left = t;

            if (c != NULL) c->Parent = t;
            t->Right = c;
            t->Left = NULL;

            tmpLevel = s->AaLevel;
            s->AaLevel = t->AaLevel;
            t->AaLevel = tmpLevel;
        }

        // reload pointers
        p = t->Parent;              // #10
        if (p != NULL)
        {
            if (t == p->Left) toChildPtr = &p->Left;
            else if (t == p->Right) toChildPtr = &p->Right;
            else
            {
                ERROR("inconsistency, node is not the left neither the right child of it's parent\n");
                status = CX_STATUS_INCONSISTENT_DATA_VALUE;
                goto cleanup;
            }
        }
        else toChildPtr = NULL;
        a = t->Left;                // #11
        b = t->Right;               // #12
    }

    // now, we have to delete a t with LEVEL 1 (leaf or non-leaf with single right child at same LEVEL 1)
    if (a != NULL)
    {
        a->Parent = p;
        if (p != NULL) *toChildPtr = a;
        else Tree->Root = a;

        t->Parent = a;
        a->Left = t;

        assert(a->Right == NULL);

        t->Left = NULL;
        assert(t->Right == NULL);

        tmpLevel = a->AaLevel;
        a->AaLevel = t->AaLevel;
        t->AaLevel = tmpLevel;

        // reload pointers
        a = NULL;
        b = NULL;

        p = t->Parent;
        if (p != NULL)
        {
            if (t == p->Left) toChildPtr = &p->Left;
            else if (t == p->Right) toChildPtr = &p->Right;
            else
            {
                ERROR("inconsistency, node is not the left neither the right child of it's parent\n");
                status = CX_STATUS_INCONSISTENT_DATA_VALUE;
                goto cleanup;
            }
        }
        else toChildPtr = NULL;
    }
    else if (b != NULL)
    {
        b->Parent = p;
        if (p != NULL) *toChildPtr = b;
        else Tree->Root = b;

        t->Parent = b;
        b->Right = t;

        assert(b->Left == NULL);

        t->Right = NULL;
        assert(t->Left == NULL);

        tmpLevel = b->AaLevel;
        b->AaLevel = t->AaLevel;
        t->AaLevel = tmpLevel;

        // reload pointers
        a = NULL;
        b = NULL;

        p = t->Parent;
        if (p != NULL)
        {
            if (t == p->Left) toChildPtr = &p->Left;
            else if (t == p->Right) toChildPtr = &p->Right;
            else
            {
                ERROR("inconsistency, node is not the left neither the right child of it's parent\n");
                status = CX_STATUS_INCONSISTENT_DATA_VALUE;
                goto cleanup;
            }
        }
        else toChildPtr = NULL;
    }

    // now, we surely delete a leaf t, with no children at all
    assert(t->AaLevel == 1);

    if (p == NULL)
    {
        // this is the very simple case: we are deleting the last node from the tree
        Tree->Root = NULL;
        Tree->NodeCount--;

        if (Tree->NodeCount != 0)
        {
            ERROR("inconsistency, non-zero node count in tree after deleting the last node (the root)\n");
            status = CX_STATUS_INCONSISTENT_DATA_VALUE;
            goto cleanup;
        }
    }
    else
    {
        // unlink from tree
        *toChildPtr = NULL;
        Tree->NodeCount--;

        // rebalance upwards (repeatedly decrease levels then skew-then-split if needed)
        status = _AaRebalanceAllAfterRemove(Tree, p);
        if (!SUCCESS(status))
        {
            LOG_FUNC_FAIL("_AaRebalanceAllAfterRemove", status);
            goto cleanup;
        }
    }

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}

/**
 * @brief   Given a node, validates that the tree starting from that node respects the AATree integrity conditions.
 *
 * This method is recursive
 *
 * @param[in]       Node                                    The node from which the validation begins
 * @param[out]      SubtreeNodeCount                        The number of child nodes of the given Node
 *
 * @return CX_STATUS_SUCCESS                                The tree passed the integrity check
 * @return CX_STATUS_INVALID_PARAMETER_1                    The input node is null
 * @return CX_STATUS_INVALID_PARAMETER_2                    The SubtreeNodeCount is null
 * @return CX_STATUS_INCONSISTENT_DATA_VALUE                The tree does not respect the integrity conditions
 */
static
NTSTATUS
_AaCheckIntegrityByNode(
    _In_ AANODE* Node,
    _Out_ DWORD *SubtreeNodeCount
    )
{
    NTSTATUS status;
    DWORD leftCount, rightCount;

    if (Node == NULL) return CX_STATUS_INVALID_PARAMETER_1;
    if (SubtreeNodeCount == NULL) return CX_STATUS_INVALID_PARAMETER_2;

    // AA integrity condition from http://en.wikipedia.org/wiki/AA_tree
    // 1) The level of every leaf node is one.
    if ((Node->Left == NULL) &&
        (Node->Right == NULL) &&
        (Node->AaLevel != 1))
    {
        ERROR("leaf node with invalid AA level (must be 1 for all leaf nodes)\n");
        status = CX_STATUS_INCONSISTENT_DATA_VALUE;
        goto cleanup;
    }

    // do we need to check left subtree?
    if (Node->Left != NULL)
    {
        status = _AaCheckIntegrityByNode(Node->Left, &leftCount);
        if (!SUCCESS(status)) goto cleanup;

        if (Node != Node->Left->Parent)
        {
            ERROR("left-child-to-parent link invalid\n");
            status = CX_STATUS_INCONSISTENT_DATA_VALUE;
            goto cleanup;
        }

        // 2) The level of every left child is exactly one less than that of its parent.
        if (Node->Left->AaLevel != (Node->AaLevel - 1))
        {
            ERROR("left-child AA-level too big (skew needed) Node %p  Key %-15I64d\n",
                Node->Left, Node->Left->Key);
            status = CX_STATUS_INCONSISTENT_DATA_VALUE;
            goto cleanup;
        }

        if (Node->Left->Key >= Node->Key)
        {
            ERROR("left-child KEY is over parent's key\n");
            status = CX_STATUS_INCONSISTENT_DATA_VALUE;
            goto cleanup;
        }
    }
    else leftCount = 0;

    // do we need to check right subtree?
    if (Node->Right != NULL)
    {
        status = _AaCheckIntegrityByNode(Node->Right, &rightCount);
        if (!SUCCESS(status)) goto cleanup;

        if (Node != Node->Right->Parent)
        {
            ERROR("right-child-to-parent link invalid\n");
            status = CX_STATUS_INCONSISTENT_DATA_VALUE;
            goto cleanup;
        }

        // 3) The level of every right child is equal to or one less than that of its parent.
        if ((Node->Right->AaLevel != Node->AaLevel) &&
            (Node->Right->AaLevel != (Node->AaLevel - 1)))
        {
            ERROR("right-child AA-level is invalid Node %p  Key %-15I64d\n",
                Node->Right, Node->Right->Key);
            status = CX_STATUS_INCONSISTENT_DATA_VALUE;
            goto cleanup;
        }

        // 4) The level of every right grandchild is strictly less than that of its grandparent.
        if ((Node->Right->Right != NULL) &&
            (Node->Right->Right->AaLevel >= Node->AaLevel))
        {
            ERROR("right-child-of-right-child AA-level too big (split needed), Node %p  Key %-15I64d\n",
                Node->Right->Right, Node->Right->Right->Key);
            status = CX_STATUS_INCONSISTENT_DATA_VALUE;
            goto cleanup;
        }

        if (Node->Right->Key <= Node->Key)
        {
            ERROR("right-child KEY is below parent's key\n");
            status = CX_STATUS_INCONSISTENT_DATA_VALUE;
            goto cleanup;
        }
    }
    else rightCount = 0;

    // 5) Every node of level greater than one has two children.
    if ((Node->AaLevel > 1) &&
        ((Node->Left == NULL) || (Node->Right == NULL)))
    {
        ERROR("nodes with AA-level over 1 must have two children\n");
        status = CX_STATUS_INCONSISTENT_DATA_VALUE;
        goto cleanup;
    }

    // return complete subtree node count
    *SubtreeNodeCount = leftCount + rightCount + 1;

    // everything done just fine
    status = CX_STATUS_SUCCESS;

cleanup:

    return status;
}


NTSTATUS
AaCheckIntegrity(
    _In_ AATREE* Tree
    )
{
    NTSTATUS status;
    DWORD nodeCount;

    if (Tree == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (Tree->Root == NULL)
    {
        if (Tree->NodeCount != 0)
        {
            ERROR("non-zero node count in empty tree\n");
            return CX_STATUS_INCONSISTENT_DATA_VALUE;
        }

        return CX_STATUS_SUCCESS;
    }

    status = _AaCheckIntegrityByNode(Tree->Root, &nodeCount);
    if (!SUCCESS(status)) return status;

    if ((INT32)nodeCount != Tree->NodeCount)
    {
        ERROR("invalid tree node count\n");
        return CX_STATUS_INCONSISTENT_DATA_VALUE;
    }

    return CX_STATUS_SUCCESS;
}

/**
 * @brief   Iterates an AATree starting from a given Node and dumps its configuration.
 *
 * This method is recursive
 *
 * @param[in]       Node                                    The AATree to be checked
 * @param[in]       Level                                   The current tree level
 *
 * @return CX_STATUS_SUCCESS                                The dump was successful
 * @return CX_STATUS_INCONSISTENT_DATA_VALUE                The input node is null
 */
static
NTSTATUS
_AaDump2(
    _In_ AANODE* Node,
    _In_ DWORD Level
    )
{

    if (Node == NULL) return CX_STATUS_INCONSISTENT_DATA_VALUE;

    // dump padding
    for (DWORD k = 0; k < Level; k++)
    {
        LOGN("  ");
    }

    // dump this node
    LOGN("%p  Key %-15I64d  Left %p  Right %p  Parent %p  Aa %d\n",
        Node, Node->Key, Node->Left, Node->Right, Node->Parent, Node->AaLevel);

    // dump subtrees
    if (Node->Left != NULL) _AaDump2(Node->Left, Level+1);
    if (Node->Right != NULL) _AaDump2(Node->Right, Level+1);

    return CX_STATUS_SUCCESS;
}


NTSTATUS
AaDump(
    _In_ AATREE* Tree
    )
{
    if (Tree == NULL) return CX_STATUS_INVALID_PARAMETER_1;

    if (Tree->Root == NULL)
    {
        LOGN("(empty-tree)\n");
        return CX_STATUS_SUCCESS;
    }

    return _AaDump2(Tree->Root, 0);
}
