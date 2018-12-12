/*
 +----------------------------------------------------------------------+
 | Swoole                                                               |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2015 The Swoole Group                             |
 +----------------------------------------------------------------------+
 |     |
 +----------------------------------------------------------------------+
 | Author: chenlehui  <763414242@qq.com>                        |
 +----------------------------------------------------------------------+
 */

#ifndef SWOOLE_FPM_H_
#define SWOOLE_FPM_H_

#include "ext/standard/file.h"
#include "zend_extensions.h"
#include "Zend/zend_list.h"

extern zend_class_entry swoole_php_runner_ce;
extern zend_class_entry *swoole_php_runner_class_entry_ptr;

static int swoole_php_request_startup();
static int swoole_php_request_shutdown();


#endif /* SWOOLE_FPM_H_ */
