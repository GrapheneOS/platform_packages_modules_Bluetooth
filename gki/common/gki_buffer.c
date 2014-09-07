/******************************************************************************
 *
 *  Copyright (C) 1999-2012 Broadcom Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/
#include <cutils/log.h>

#include "allocator.h"
#include "gki_int.h"

#if (GKI_NUM_TOTAL_BUF_POOLS > 16)
#error Number of pools out of range (16 Max)!
#endif

#define ALIGN_POOL(pl_size)  ( (((pl_size) + 3) / sizeof(UINT32)) * sizeof(UINT32))
#define BUFFER_HDR_SIZE     (sizeof(BUFFER_HDR_T))                  /* Offset past header */
#define BUFFER_PADDING_SIZE (sizeof(BUFFER_HDR_T) + sizeof(UINT32)) /* Header + Magic Number */
#define MAGIC_NO            0xDDBADDBA

#define BUF_STATUS_FREE     0
#define BUF_STATUS_UNLINKED 1
#define BUF_STATUS_QUEUED   2

/*******************************************************************************
**
** Function         gki_init_free_queue
**
** Description      Internal function called at startup to initialize a free
**                  queue. It is called once for each free queue.
**
** Returns          void
**
*******************************************************************************/
static void gki_init_free_queue (UINT8 id, UINT16 size, UINT16 total, void *p_mem)
{
    UINT16           i;
    UINT16           act_size;
    BUFFER_HDR_T    *hdr;
    BUFFER_HDR_T    *hdr1 = NULL;
    UINT32          *magic;
    INT32            tempsize = size;
    tGKI_COM_CB     *p_cb = &gki_cb.com;

    /* Ensure an even number of longwords */
    tempsize = (INT32)ALIGN_POOL(size);
    act_size = (UINT16)(tempsize + BUFFER_PADDING_SIZE);

    /* Remember pool start and end addresses */
    if(p_mem)
    {
        p_cb->pool_start[id] = (UINT8 *)p_mem;
        p_cb->pool_end[id]   = (UINT8 *)p_mem + (act_size * total);
    }

    p_cb->pool_size[id]  = act_size;

    p_cb->freeq[id].size      = (UINT16) tempsize;
    p_cb->freeq[id].total     = total;
    p_cb->freeq[id].cur_cnt   = 0;
    p_cb->freeq[id].max_cnt   = 0;

    /* Initialize  index table */
    if(p_mem)
    {
        hdr = (BUFFER_HDR_T *)p_mem;
        p_cb->freeq[id]._p_first = hdr;
        for (i = 0; i < total; i++)
        {
            hdr->task_id = GKI_INVALID_TASK;
            hdr->q_id    = id;
            hdr->status  = BUF_STATUS_FREE;
            magic        = (UINT32 *)((UINT8 *)hdr + BUFFER_HDR_SIZE + tempsize);
            *magic       = MAGIC_NO;
            hdr1         = hdr;
            hdr          = (BUFFER_HDR_T *)((UINT8 *)hdr + act_size);
            hdr1->p_next = hdr;
        }
        hdr1->p_next = NULL;
        p_cb->freeq[id]._p_last = hdr1;
    }
}

#if !VALGRIND
static BOOLEAN gki_alloc_free_queue(UINT8 id)
{
    FREE_QUEUE_T  *Q;
    tGKI_COM_CB *p_cb = &gki_cb.com;
    GKI_TRACE("\ngki_alloc_free_queue in, id:%d \n", (int)id );

    Q = &p_cb->freeq[id];

    if(Q->_p_first == 0)
    {
        void* p_mem = osi_malloc((Q->size + BUFFER_PADDING_SIZE) * Q->total);
        if(p_mem)
        {
            //re-initialize the queue with allocated memory
            GKI_TRACE("\ngki_alloc_free_queue calling  gki_init_free_queue, id:%d  size:%d, totol:%d\n", id, Q->size, Q->total);
            gki_init_free_queue(id, Q->size, Q->total, p_mem);
            GKI_TRACE("\ngki_alloc_free_queue ret OK, id:%d  size:%d, totol:%d\n", id, Q->size, Q->total);
            return TRUE;
        }
        GKI_exception (GKI_ERROR_BUF_SIZE_TOOBIG, "gki_alloc_free_queue: Not enough memory");
    }
    GKI_TRACE("\ngki_alloc_free_queue out failed, id:%d\n", id);
    return FALSE;
}
#endif

void gki_dealloc_free_queue(void)
{
    UINT8   i;
    tGKI_COM_CB *p_cb = &gki_cb.com;

    for (i=0; i < GKI_NUM_FIXED_BUF_POOLS; i++)
    {
        if ( 0 < p_cb->freeq[i].max_cnt )
        {
            osi_free(p_cb->pool_start[i]);

            p_cb->freeq[i].cur_cnt   = 0;
            p_cb->freeq[i].max_cnt   = 0;
            p_cb->freeq[i]._p_first   = NULL;
            p_cb->freeq[i]._p_last    = NULL;

            p_cb->pool_start[i] = NULL;
            p_cb->pool_end[i]   = NULL;
            p_cb->pool_size[i]  = 0;
        }
    }
}

/*******************************************************************************
**
** Function         gki_buffer_init
**
** Description      Called once internally by GKI at startup to initialize all
**                  buffers and free buffer pools.
**
** Returns          void
**
*******************************************************************************/
void gki_buffer_init(void)
{
    static const struct {
      uint16_t size;
      uint16_t count;
    } buffer_info[GKI_NUM_FIXED_BUF_POOLS] = {
      { GKI_BUF0_SIZE, GKI_BUF0_MAX },
      { GKI_BUF1_SIZE, GKI_BUF1_MAX },
      { GKI_BUF2_SIZE, GKI_BUF2_MAX },
      { GKI_BUF3_SIZE, GKI_BUF3_MAX },
      { GKI_BUF4_SIZE, GKI_BUF4_MAX },
      { GKI_BUF5_SIZE, GKI_BUF5_MAX },
      { GKI_BUF6_SIZE, GKI_BUF6_MAX },
      { GKI_BUF7_SIZE, GKI_BUF7_MAX },
      { GKI_BUF8_SIZE, GKI_BUF8_MAX },
      { GKI_BUF9_SIZE, GKI_BUF9_MAX },
    };

    UINT8   i, tt, mb;
    tGKI_COM_CB *p_cb = &gki_cb.com;

    for (tt = 0; tt < GKI_NUM_TOTAL_BUF_POOLS; tt++)
    {
        p_cb->pool_start[tt] = NULL;
        p_cb->pool_end[tt]   = NULL;
        p_cb->pool_size[tt]  = 0;

        p_cb->freeq[tt]._p_first = 0;
        p_cb->freeq[tt]._p_last  = 0;
        p_cb->freeq[tt].size    = 0;
        p_cb->freeq[tt].total   = 0;
        p_cb->freeq[tt].cur_cnt = 0;
        p_cb->freeq[tt].max_cnt = 0;
    }

    /* Use default from target.h */
    p_cb->pool_access_mask = GKI_DEF_BUFPOOL_PERM_MASK;

    for (int i = 0; i < GKI_NUM_FIXED_BUF_POOLS; ++i) {
      gki_init_free_queue(i, buffer_info[i].size, buffer_info[i].count, NULL);
    }
}

/*******************************************************************************
**
** Function         GKI_init_q
**
** Description      Called by an application to initialize a buffer queue.
**
** Returns          void
**
*******************************************************************************/
void GKI_init_q (BUFFER_Q *p_q)
{
    p_q->_p_first = p_q->_p_last = NULL;
    p_q->_count = 0;
}

/*******************************************************************************
**
** Function         GKI_getbuf
**
** Description      Called by an application to get a free buffer which
**                  is of size greater or equal to the requested size.
**
**                  Note: This routine only takes buffers from public pools.
**                        It will not use any buffers from pools
**                        marked GKI_RESTRICTED_POOL.
**
** Parameters       size - (input) number of bytes needed.
**
** Returns          A pointer to the buffer, or NULL if none available
**
*******************************************************************************/
void *GKI_getbuf (UINT16 size)
{
#if VALGRIND
  BUFFER_HDR_T *header = malloc(size + BUFFER_HDR_SIZE);
  header->task_id = GKI_get_taskid();
  header->status  = BUF_STATUS_UNLINKED;
  header->p_next  = NULL;
  header->Type    = 0;
  header->size = size;
  return header + 1;
#else
    UINT8         i;
    FREE_QUEUE_T  *Q;
    BUFFER_HDR_T  *p_hdr;
    tGKI_COM_CB *p_cb = &gki_cb.com;

    if (size == 0)
    {
        GKI_exception (GKI_ERROR_BUF_SIZE_ZERO, "getbuf: Size is zero");
        return (NULL);
    }

    /* Find the first buffer pool that is public that can hold the desired size */
    for (i=0; i < GKI_NUM_FIXED_BUF_POOLS; i++)
    {
        if ( size <= p_cb->freeq[i].size )
            break;
    }

    if(i == GKI_NUM_FIXED_BUF_POOLS)
    {
        GKI_exception (GKI_ERROR_BUF_SIZE_TOOBIG, "getbuf: Size is too big");
        return (NULL);
    }

    /* Make sure the buffers aren't disturbed til finished with allocation */
    GKI_disable();

    /* search the public buffer pools that are big enough to hold the size
     * until a free buffer is found */
    for ( ; i < GKI_NUM_FIXED_BUF_POOLS; i++)
    {
        /* Only look at PUBLIC buffer pools (bypass RESTRICTED pools) */
        if (((UINT16)1 << i) & p_cb->pool_access_mask)
            continue;
        if ( size <= p_cb->freeq[i].size )
             Q = &p_cb->freeq[i];
        else
             continue;

        if(Q->cur_cnt < Q->total)
        {
            if(Q->_p_first == 0 && gki_alloc_free_queue(i) != TRUE) {
                GKI_enable();
                return NULL;
            }
            p_hdr = Q->_p_first;
            Q->_p_first = p_hdr->p_next;

            if (!Q->_p_first)
                Q->_p_last = NULL;

            if(++Q->cur_cnt > Q->max_cnt)
                Q->max_cnt = Q->cur_cnt;

            GKI_enable();

            p_hdr->task_id = GKI_get_taskid();

            p_hdr->status  = BUF_STATUS_UNLINKED;
            p_hdr->p_next  = NULL;
            p_hdr->Type    = 0;

            return ((void *) ((UINT8 *)p_hdr + BUFFER_HDR_SIZE));
        }
    }

    GKI_enable();

    GKI_exception (GKI_ERROR_OUT_OF_BUFFERS, "getbuf: out of buffers");
    return (NULL);
#endif
}


/*******************************************************************************
**
** Function         GKI_getpoolbuf
**
** Description      Called by an application to get a free buffer from
**                  a specific buffer pool.
**
**                  Note: If there are no more buffers available from the pool,
**                        the public buffers are searched for an available buffer.
**
** Parameters       pool_id - (input) pool ID to get a buffer out of.
**
** Returns          A pointer to the buffer, or NULL if none available
**
*******************************************************************************/
void *GKI_getpoolbuf (UINT8 pool_id)
{
#if VALGRIND
  return GKI_getbuf(gki_cb.com.pool_size[pool_id]);
#else
    FREE_QUEUE_T  *Q;
    BUFFER_HDR_T  *p_hdr;
    tGKI_COM_CB *p_cb = &gki_cb.com;

    if (pool_id >= GKI_NUM_TOTAL_BUF_POOLS)
    {
        GKI_exception(GKI_ERROR_GETPOOLBUF_BAD_QID, "getpoolbuf bad pool");
        return (NULL);
    }

    /* Make sure the buffers aren't disturbed til finished with allocation */
    GKI_disable();

    Q = &p_cb->freeq[pool_id];
    if(Q->cur_cnt < Q->total)
    {
        if(Q->_p_first == 0 && gki_alloc_free_queue(pool_id) != TRUE) {
            GKI_enable();
            return NULL;
        }
        p_hdr = Q->_p_first;
        Q->_p_first = p_hdr->p_next;

        if (!Q->_p_first)
            Q->_p_last = NULL;

        if(++Q->cur_cnt > Q->max_cnt)
            Q->max_cnt = Q->cur_cnt;

        GKI_enable();


        p_hdr->task_id = GKI_get_taskid();

        p_hdr->status  = BUF_STATUS_UNLINKED;
        p_hdr->p_next  = NULL;
        p_hdr->Type    = 0;

        return ((void *) ((UINT8 *)p_hdr + BUFFER_HDR_SIZE));
    }

    /* If here, no buffers in the specified pool */
    GKI_enable();

    /* try for free buffers in public pools */
    return (GKI_getbuf(p_cb->freeq[pool_id].size));
#endif
}

/*******************************************************************************
**
** Function         GKI_freebuf
**
** Description      Called by an application to return a buffer to the free pool.
**
** Parameters       p_buf - (input) address of the beginning of a buffer.
**
** Returns          void
**
*******************************************************************************/
void GKI_freebuf (void *p_buf)
{
#if VALGRIND
  free((BUFFER_HDR_T *)p_buf - 1);
#else
    FREE_QUEUE_T    *Q;
    BUFFER_HDR_T    *p_hdr;

#if (GKI_ENABLE_BUF_CORRUPTION_CHECK == TRUE)
    if (!p_buf || gki_chk_buf_damage(p_buf))
    {
        GKI_exception(GKI_ERROR_BUF_CORRUPTED, "Free - Buf Corrupted");
        return;
    }
#endif

    p_hdr = (BUFFER_HDR_T *) ((UINT8 *)p_buf - BUFFER_HDR_SIZE);

    if (p_hdr->q_id >= GKI_NUM_TOTAL_BUF_POOLS)
    {
        GKI_exception(GKI_ERROR_FREEBUF_BAD_QID, "Bad Buf QId");
        return;
    }

    GKI_disable();

    /*
    ** Release the buffer
    */
    Q  = &gki_cb.com.freeq[p_hdr->q_id];
    if (Q->_p_last)
        Q->_p_last->p_next = p_hdr;
    else
        Q->_p_first = p_hdr;

    Q->_p_last      = p_hdr;
    p_hdr->p_next  = NULL;
    p_hdr->status  = BUF_STATUS_FREE;
    p_hdr->task_id = GKI_INVALID_TASK;
    if (Q->cur_cnt > 0)
        Q->cur_cnt--;

    GKI_enable();
#endif
}


/*******************************************************************************
**
** Function         GKI_get_buf_size
**
** Description      Called by an application to get the size of a buffer.
**
** Parameters       p_buf - (input) address of the beginning of a buffer.
**
** Returns          the size of the buffer
**
*******************************************************************************/
UINT16 GKI_get_buf_size (void *p_buf)
{
#if VALGRIND
  BUFFER_HDR_T *header = (BUFFER_HDR_T *)p_buf - 1;
  return header->size;
#else
    BUFFER_HDR_T    *p_hdr;

    p_hdr = (BUFFER_HDR_T *)((UINT8 *) p_buf - BUFFER_HDR_SIZE);

    if ((UINT32)p_hdr & 1)
        return (0);

    if (p_hdr->q_id < GKI_NUM_TOTAL_BUF_POOLS)
    {
        return (gki_cb.com.freeq[p_hdr->q_id].size);
    }

    return (0);
#endif
}

/*******************************************************************************
**
** Function         gki_chk_buf_damage
**
** Description      Called internally by OSS to check for buffer corruption.
**
** Returns          TRUE if there is a problem, else FALSE
**
*******************************************************************************/
BOOLEAN gki_chk_buf_damage(void *p_buf)
{
#if (GKI_ENABLE_BUF_CORRUPTION_CHECK == TRUE) && !VALGRIND

    UINT32 *magic;
    magic  = (UINT32 *)((UINT8 *) p_buf + GKI_get_buf_size(p_buf));

    if ((UINT32)magic & 1)
        return (TRUE);

    if (*magic == MAGIC_NO)
        return (FALSE);

    return (TRUE);

#else

    (void)p_buf;
    return (FALSE);

#endif
}

/*******************************************************************************
**
** Function         GKI_enqueue
**
** Description      Enqueue a buffer at the tail of the queue
**
** Parameters:      p_q  -  (input) pointer to a queue.
**                  p_buf - (input) address of the buffer to enqueue
**
** Returns          void
**
*******************************************************************************/
void GKI_enqueue (BUFFER_Q *p_q, void *p_buf)
{
    BUFFER_HDR_T    *p_hdr;

#if (GKI_ENABLE_BUF_CORRUPTION_CHECK == TRUE)
    if (gki_chk_buf_damage(p_buf))
    {
        GKI_exception(GKI_ERROR_BUF_CORRUPTED, "Enqueue - Buffer corrupted");
        return;
    }
#endif

    p_hdr = (BUFFER_HDR_T *) ((UINT8 *) p_buf - BUFFER_HDR_SIZE);

    if (p_hdr->status != BUF_STATUS_UNLINKED)
    {
        GKI_exception(GKI_ERROR_ENQUEUE_BUF_LINKED, "Eneueue - buf already linked");
        return;
    }

    GKI_disable();

    /* Since the queue is exposed (C vs C++), keep the pointers in exposed format */
    if (p_q->_p_last)
    {
        BUFFER_HDR_T *_p_last_hdr = (BUFFER_HDR_T *)((UINT8 *)p_q->_p_last - BUFFER_HDR_SIZE);
        _p_last_hdr->p_next = p_hdr;
    }
    else
        p_q->_p_first = p_buf;

    p_q->_p_last = p_buf;
    p_q->_count++;

    p_hdr->p_next = NULL;
    p_hdr->status = BUF_STATUS_QUEUED;

    GKI_enable();
}


/*******************************************************************************
**
** Function         GKI_enqueue_head
**
** Description      Enqueue a buffer at the head of the queue
**
** Parameters:      p_q  -  (input) pointer to a queue.
**                  p_buf - (input) address of the buffer to enqueue
**
** Returns          void
**
*******************************************************************************/
void GKI_enqueue_head (BUFFER_Q *p_q, void *p_buf)
{
    BUFFER_HDR_T    *p_hdr;

#if (GKI_ENABLE_BUF_CORRUPTION_CHECK == TRUE)
    if (gki_chk_buf_damage(p_buf))
    {
        GKI_exception(GKI_ERROR_BUF_CORRUPTED, "Enqueue - Buffer corrupted");
        return;
    }
#endif

    p_hdr = (BUFFER_HDR_T *) ((UINT8 *) p_buf - BUFFER_HDR_SIZE);

    if (p_hdr->status != BUF_STATUS_UNLINKED)
    {
        GKI_exception(GKI_ERROR_ENQUEUE_BUF_LINKED, "Eneueue head - buf already linked");
        return;
    }

    GKI_disable();

    if (p_q->_p_first)
    {
        p_hdr->p_next = (BUFFER_HDR_T *)((UINT8 *)p_q->_p_first - BUFFER_HDR_SIZE);
        p_q->_p_first = p_buf;
    }
    else
    {
        p_q->_p_first = p_buf;
        p_q->_p_last  = p_buf;
        p_hdr->p_next = NULL;
    }
    p_q->_count++;

    p_hdr->status = BUF_STATUS_QUEUED;

    GKI_enable();

    return;
}


/*******************************************************************************
**
** Function         GKI_dequeue
**
** Description      Dequeues a buffer from the head of a queue
**
** Parameters:      p_q  - (input) pointer to a queue.
**
** Returns          NULL if queue is empty, else buffer
**
*******************************************************************************/
void *GKI_dequeue (BUFFER_Q *p_q)
{
    BUFFER_HDR_T    *p_hdr;

    GKI_disable();

    if (!p_q || !p_q->_count)
    {
        GKI_enable();
        return (NULL);
    }

    p_hdr = (BUFFER_HDR_T *)((UINT8 *)p_q->_p_first - BUFFER_HDR_SIZE);

    /* Keep buffers such that GKI header is invisible
    */
    if (p_hdr->p_next)
        p_q->_p_first = ((UINT8 *)p_hdr->p_next + BUFFER_HDR_SIZE);
    else
    {
        p_q->_p_first = NULL;
        p_q->_p_last  = NULL;
    }

    p_q->_count--;

    p_hdr->p_next = NULL;
    p_hdr->status = BUF_STATUS_UNLINKED;

    GKI_enable();

    return ((UINT8 *)p_hdr + BUFFER_HDR_SIZE);
}

/*******************************************************************************
**
** Function         GKI_remove_from_queue
**
** Description      Dequeue a buffer from the middle of the queue
**
** Parameters:      p_q  - (input) pointer to a queue.
**                  p_buf - (input) address of the buffer to enqueue
**
** Returns          NULL if queue is empty, else buffer
**
*******************************************************************************/
void *GKI_remove_from_queue (BUFFER_Q *p_q, void *p_buf)
{
    BUFFER_HDR_T    *p_prev;
    BUFFER_HDR_T    *p_buf_hdr;

    GKI_disable();

    if (p_buf == p_q->_p_first)
    {
        GKI_enable();
        return (GKI_dequeue (p_q));
    }

    p_buf_hdr = (BUFFER_HDR_T *)((UINT8 *)p_buf - BUFFER_HDR_SIZE);
    p_prev    = (BUFFER_HDR_T *)((UINT8 *)p_q->_p_first - BUFFER_HDR_SIZE);

    for ( ; p_prev; p_prev = p_prev->p_next)
    {
        /* If the previous points to this one, move the pointers around */
        if (p_prev->p_next == p_buf_hdr)
        {
            p_prev->p_next = p_buf_hdr->p_next;

            /* If we are removing the last guy in the queue, update _p_last */
            if (p_buf == p_q->_p_last)
                p_q->_p_last = p_prev + 1;

            /* One less in the queue */
            p_q->_count--;

            /* The buffer is now unlinked */
            p_buf_hdr->p_next = NULL;
            p_buf_hdr->status = BUF_STATUS_UNLINKED;

            GKI_enable();
            return (p_buf);
        }
    }

    GKI_enable();
    return (NULL);
}

/*******************************************************************************
**
** Function         GKI_getfirst
**
** Description      Return a pointer to the first buffer in a queue
**
** Parameters:      p_q  - (input) pointer to a queue.
**
** Returns          NULL if queue is empty, else buffer address
**
*******************************************************************************/
void *GKI_getfirst (BUFFER_Q *p_q)
{
    return (p_q->_p_first);
}

/*******************************************************************************
**
** Function         GKI_getlast
**
** Description      Return a pointer to the last buffer in a queue
**
** Parameters:      p_q  - (input) pointer to a queue.
**
** Returns          NULL if queue is empty, else buffer address
**
*******************************************************************************/
void *GKI_getlast (BUFFER_Q *p_q)
{
    return (p_q->_p_last);
}

/*******************************************************************************
**
** Function         GKI_getnext
**
** Description      Return a pointer to the next buffer in a queue
**
** Parameters:      p_buf  - (input) pointer to the buffer to find the next one from.
**
** Returns          NULL if no more buffers in the queue, else next buffer address
**
*******************************************************************************/
void *GKI_getnext (void *p_buf)
{
    BUFFER_HDR_T    *p_hdr;

    p_hdr = (BUFFER_HDR_T *) ((UINT8 *) p_buf - BUFFER_HDR_SIZE);

    if (p_hdr->p_next)
        return ((UINT8 *)p_hdr->p_next + BUFFER_HDR_SIZE);
    else
        return (NULL);
}

/*******************************************************************************
**
** Function         GKI_queue_is_empty
**
** Description      Check the status of a queue.
**
** Parameters:      p_q  - (input) pointer to a queue.
**
** Returns          TRUE if queue is empty, else FALSE
**
*******************************************************************************/
BOOLEAN GKI_queue_is_empty(BUFFER_Q *p_q)
{
    return ((BOOLEAN) (p_q->_count == 0));
}

UINT16 GKI_queue_length(BUFFER_Q *p_q)
{
    return p_q->_count;
}

/*******************************************************************************
**
** Function         GKI_poolcount
**
** Description      Called by an application to get the total number of buffers
**                  in the specified buffer pool.
**
** Parameters       pool_id - (input) pool ID to get the free count of.
**
** Returns          the total number of buffers in the pool
**
*******************************************************************************/
UINT16 GKI_poolcount (UINT8 pool_id)
{
    if (pool_id >= GKI_NUM_TOTAL_BUF_POOLS)
        return (0);

    return (gki_cb.com.freeq[pool_id].total);
}

/*******************************************************************************
**
** Function         GKI_poolfreecount
**
** Description      Called by an application to get the number of free buffers
**                  in the specified buffer pool.
**
** Parameters       pool_id - (input) pool ID to get the free count of.
**
** Returns          the number of free buffers in the pool
**
*******************************************************************************/
UINT16 GKI_poolfreecount (UINT8 pool_id)
{
    FREE_QUEUE_T  *Q;

    if (pool_id >= GKI_NUM_TOTAL_BUF_POOLS)
        return (0);

    Q  = &gki_cb.com.freeq[pool_id];

    return ((UINT16)(Q->total - Q->cur_cnt));
}

/*******************************************************************************
**
** Function         GKI_get_pool_bufsize
**
** Description      Called by an application to get the size of buffers in a pool
**
** Parameters       Pool ID.
**
** Returns          the size of buffers in the pool
**
*******************************************************************************/
UINT16 GKI_get_pool_bufsize (UINT8 pool_id)
{
    if (pool_id < GKI_NUM_TOTAL_BUF_POOLS)
        return (gki_cb.com.freeq[pool_id].size);

    return (0);
}

/*******************************************************************************
**
** Function         GKI_poolutilization
**
** Description      Called by an application to get the buffer utilization
**                  in the specified buffer pool.
**
** Parameters       pool_id - (input) pool ID to get the free count of.
**
** Returns          % of buffers used from 0 to 100
**
*******************************************************************************/
UINT16 GKI_poolutilization (UINT8 pool_id)
{
    FREE_QUEUE_T  *Q;

    if (pool_id >= GKI_NUM_TOTAL_BUF_POOLS)
        return (100);

    Q  = &gki_cb.com.freeq[pool_id];

    if (Q->total == 0)
        return (100);

    return ((Q->cur_cnt * 100) / Q->total);
}
