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

#ifndef SWOOLE_PHP_RUNNER_H_
#define SWOOLE_PHP_RUNNER_H_

#include "ext/standard/file.h"
#include "zend_extensions.h"
#include "Zend/zend_list.h"
#include "php_variables.h"
#include "zend_globals_macros.h"
#include "Zend/zend_language_scanner.h"

int swoole_php_request_startup();
int swoole_php_request_shutdown();
zval * class_call_user_method(zval *retval, zend_class_entry *obj_ce, 
        zval *obj, zval function_name,  uint32_t params_count, zval params[]); 

#endif /* SWOOLE_PHP_RUNNER_H_ */
