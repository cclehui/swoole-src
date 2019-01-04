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

typedef struct _server_receive_context {
    zval *zserv; // object of swoole_server
    zval *zfd;
    zval *zfrom_id;
    zend_string *zdata;
} server_receive_context;

//调用对象中方法
// zval function_name;
// ZVAL_STRING(&function_name,"set");
zval * class_call_user_method(zval *retval, zend_class_entry *obj_ce, 
        zval *obj, zval function_name,  uint32_t params_count, zval params[]){ 

    zend_fcall_info fci;  

    fci.size = sizeof(fci);  
    fci.function_name = function_name;   
    fci.retval = retval;  
    fci.params = params;  
    fci.object =  obj ? Z_OBJ_P(obj) : NULL;;
    fci.param_count = params_count;  
    fci.no_separation = 1;  

    int result;
    result = zend_call_function(&fci, NULL TSRMLS_CC);         //函数调用结束。  

    if (result == FAILURE) {
        swoole_php_fatal_error(E_ERROR, "function call failed. Error: %s", sw_error);
    }

    return retval;
}

#endif /* SWOOLE_FPM_H_ */
