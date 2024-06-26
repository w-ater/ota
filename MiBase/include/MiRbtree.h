#ifndef	_LINUX_RBTREE_H_
#define	_LINUX_RBTREE_H_
#include "MiUtil.h"



#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#pragma pack(push,4)
struct rb_node
{
	unsigned long  rb_parent_color;
#define	RB_RED		0
#define	RB_BLACK	1
	struct rb_node* rb_right;
	struct rb_node* rb_left;
};
//__attribute__((aligned(sizeof(long))));
/* The alignment might seem pointless, but allegedly CRIS needs it */
#pragma pack(pop)
struct rb_root
{
	struct rb_node* rb_node;
};


#define rb_parent(r)   ((struct rb_node *)((r)->rb_parent_color & ~3))
#define rb_color(r)   ((r)->rb_parent_color & 1)
#define rb_is_red(r)   (!rb_color(r))
#define rb_is_black(r) rb_color(r)
#define rb_set_red(r)  do { (r)->rb_parent_color &= ~1; } while (0)
#define rb_set_black(r)  do { (r)->rb_parent_color |= 1; } while (0)

static inline void rb_set_parent(struct rb_node* rb, struct rb_node* p)
{
	rb->rb_parent_color = (rb->rb_parent_color & 3) | (unsigned long)p;
}
static inline void rb_set_color(struct rb_node* rb, int color)
{
	rb->rb_parent_color = (rb->rb_parent_color & ~1) | color;
}

#define RB_ROOT	(struct rb_root) { NULL, }
#define	rb_entry(ptr, type, member) container_of(ptr, type, member)

#define RB_EMPTY_ROOT(root)	((root)->rb_node == NULL)
#define RB_EMPTY_NODE(node)	(rb_parent(node) == node)
#define RB_CLEAR_NODE(node)	(rb_set_parent(node, node))

extern void rb_insert_color(struct rb_node*, struct rb_root*);
extern void rb_erase(struct rb_node*, struct rb_root*);

/* Find logical next and previous nodes in a tree */
extern struct rb_node* rb_next(struct rb_node*);
extern struct rb_node* rb_prev(struct rb_node*);
extern struct rb_node* rb_first(struct rb_root*);
extern struct rb_node* rb_last(struct rb_root*);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
extern void rb_replace_node(struct rb_node* victim, struct rb_node* newx,
	struct rb_root* root);

static inline void rb_link_node(struct rb_node* node, struct rb_node* parent,
	struct rb_node** rb_link)
{
	node->rb_parent_color = (unsigned long)parent;
	node->rb_left = node->rb_right = NULL;

	*rb_link = node;
}

#endif
