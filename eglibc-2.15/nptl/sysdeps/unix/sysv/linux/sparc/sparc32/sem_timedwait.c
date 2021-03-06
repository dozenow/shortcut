/* sem_timedwait -- wait on a semaphore.  SPARC version.
   Copyright (C) 2003, 2006, 2007 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Paul Mackerras <paulus@au.ibm.com>, 2003.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <errno.h>
#include <sysdep.h>
#include <lowlevellock.h>
#include <internaltypes.h>
#include <semaphore.h>

#include <pthreadP.h>
#include <shlib-compat.h>


extern void __sem_wait_cleanup (void *arg) attribute_hidden;

/* This is in a seperate function in order to make sure gcc
   puts the call site into an exception region, and thus the
   cleanups get properly run.  */
static int
__attribute__ ((noinline))
do_futex_timed_wait (struct sparc_new_sem *isem, struct timespec *rt)
{
  int err, oldtype = __pthread_enable_asynccancel ();

  err = lll_futex_timed_wait (&isem->value, 0, rt,
			      isem->private ^ FUTEX_PRIVATE_FLAG);

  __pthread_disable_asynccancel (oldtype);
  return err;
}

int
sem_timedwait (sem_t *sem, const struct timespec *abstime)
{
  struct sparc_new_sem *isem = (struct sparc_new_sem *) sem;
  int err;
  int val;

  if (__atomic_is_v9)
    val = atomic_decrement_if_positive (&isem->value);
  else
    {
      __sparc32_atomic_do_lock24 (&isem->lock);
      val = isem->value;
      if (val > 0)
        isem->value = val - 1;
      __sparc32_atomic_do_unlock24 (&isem->lock);
    }

  if (val > 0)
    return 0;

  if (abstime->tv_nsec < 0 || abstime->tv_nsec >= 1000000000)
    {
      __set_errno (EINVAL);
      return -1;
    }

  if (__atomic_is_v9)
    atomic_increment (&isem->nwaiters);
  else
    {
      __sparc32_atomic_do_lock24 (&isem->lock);
      isem->nwaiters++;
      __sparc32_atomic_do_unlock24 (&isem->lock);
    }

  pthread_cleanup_push (__sem_wait_cleanup, isem);

  while (1)
    {
      struct timeval tv;
      struct timespec rt;
      int sec, nsec;

      /* Get the current time.  */
      __gettimeofday (&tv, NULL);

      /* Compute relative timeout.  */
      sec = abstime->tv_sec - tv.tv_sec;
      nsec = abstime->tv_nsec - tv.tv_usec * 1000;
      if (nsec < 0)
	{
	  nsec += 1000000000;
	  --sec;
	}

      /* Already timed out?  */
      err = -ETIMEDOUT;
      if (sec < 0)
	{
	  __set_errno (ETIMEDOUT);
	  err = -1;
	  break;
	}

      /* Do wait.  */
      rt.tv_sec = sec;
      rt.tv_nsec = nsec;
      err = do_futex_timed_wait(isem, &rt);
      if (err != 0 && err != -EWOULDBLOCK)
	{
	  __set_errno (-err);
	  err = -1;
	  break;
	}

      if (__atomic_is_v9)
	val = atomic_decrement_if_positive (&isem->value);
      else
	{
	  __sparc32_atomic_do_lock24 (&isem->lock);
	  val = isem->value;
	  if (val > 0)
	    isem->value = val - 1;
	  __sparc32_atomic_do_unlock24 (&isem->lock);
	}

      if (val > 0)
	{
	  err = 0;
	  break;
	}
    }

  pthread_cleanup_pop (0);

  if (__atomic_is_v9)
    atomic_decrement (&isem->nwaiters);
  else
    {
      __sparc32_atomic_do_lock24 (&isem->lock);
      isem->nwaiters--;
      __sparc32_atomic_do_unlock24 (&isem->lock);
    }

  return err;
}
