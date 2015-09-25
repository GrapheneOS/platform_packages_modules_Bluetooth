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

#include <assert.h>
#include <stdlib.h>

#include "osi/include/allocator.h"
#include "gki.h"

typedef struct _buffer_hdr
{
	UINT8   q_id;                 /* id of the queue */
        UINT16  size;
} BUFFER_HDR_T;

#define BUFFER_HDR_SIZE     (sizeof(BUFFER_HDR_T))                  /* Offset past header */

/*******************************************************************************
**
** Function         GKI_getbuf
**
** Description      Called by an application to get a free buffer which
**                  is of size greater or equal to the requested size.
**
** Parameters       size - (input) number of bytes needed.
**
** Returns          A pointer to the buffer, or NULL if none available
**
*******************************************************************************/
void *GKI_getbuf (UINT16 size)
{
  BUFFER_HDR_T *header = osi_malloc(size + BUFFER_HDR_SIZE);
  header->size = size;
  return header + 1;
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
  osi_free((BUFFER_HDR_T *)p_buf - 1);
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
  BUFFER_HDR_T *header = (BUFFER_HDR_T *)p_buf - 1;
  return header->size;
}
