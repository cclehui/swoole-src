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

#include "php_swoole.h"
#include "swoole_php_runner.h"
#include "PhpRunner.h"
#include "php_variables.h"
#include "zend_globals_macros.h"
#include "Zend/zend_language_scanner.h"

zend_class_entry swoole_php_runner_ce;
zend_class_entry *swoole_php_runner_class_entry_ptr;

static PHP_METHOD(swoole_php_runner, run);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_php_runner_run, 0, 0, 2)
ZEND_END_ARG_INFO()


const zend_function_entry swoole_php_runner_methods[] =
{
    PHP_ME(swoole_php_runner, run,         arginfo_swoole_php_runner_run, ZEND_ACC_PUBLIC|ZEND_ACC_STATIC)
    PHP_FE_END
};


void swoole_php_runner_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_php_runner_ce, "swoole_php_runner", "Swoole\\Php\\Runner", swoole_php_runner_methods);
    //swoole_php_runner_class_entry_ptr = sw_zend_register_internal_class_ex(&swoole_php_runner_ce, swoole_server_class_entry_ptr, "swoole_server" TSRMLS_CC);
    swoole_php_runner_class_entry_ptr = zend_register_internal_class(&swoole_php_runner_ce TSRMLS_CC);
    SWOOLE_CLASS_ALIAS(swoole_php_runner, "Swoole\\Fpm\\Server");

}

static size_t sapi_cli_ub_write(const char *str, size_t str_length) /* {{{ */
{
    zval send_data;
    //SW_ZVAL_STRING(&send_data, "sssssssssssssssdddddddddddddddd", 1); 
    SW_ZVAL_STRINGL(&send_data, str, str_length, 1); 


    server_receive_context *receive_context = (server_receive_context *)SG(server_context);
    zval *zserv = receive_context->zserv;

    zval send_retval;
    zval function_name;
    ZVAL_STRING(&function_name, "send");

    zval params[2];
    params[0] = *(receive_context->zfd);
    params[1] = send_data;

    //调用 swoole_server->send() 方法 输出 output
    class_call_user_method(&send_retval, swoole_server_class_entry_ptr, zserv, function_name, 2, params);

    //swNotice("sapi_cli_ub_write, ooooooooooo , %s", str);

    /*
    if (output_buffer == NULL) {
        output_buffer = zend_string_init(str, str_length, 0);

    } else {
        size_t old_length = ZSTR_LEN(output_buffer);
        output_buffer = zend_string_realloc(output_buffer, old_length + str_length, 0);
        memcpy(ZSTR_VAL(output_buffer) + old_length, str, str_length);
    }
    */

    return str_length;
}

static void sapi_cli_flush(void *server_context) /* {{{ */
{
    if (output_buffer != NULL) {
        zend_string_free(output_buffer);
    }
}

static void sapi_cli_log_message(char *message, int syslog_type_int) /* {{{ */
{
    swWarn("sapi_cli_log_message, %s\n", message);
}


//执行php程序
static PHP_METHOD(swoole_php_runner, run)
{

    zval *zserv;
    zval *zfd;
    zval *zfrom_id;
    zend_string *zdata;
    

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zzzS", &zserv, &zfd, &zfrom_id, &zdata) == FAILURE) {
        goto out;
    }

    if (!zserv) {
        swWarn("serv object is null");
        goto out;
    }

    //sapi 的output输出处理赋值
    sapi_module.ub_write = sapi_cli_ub_write;
    sapi_module.flush = sapi_cli_flush;
    sapi_module.log_message = sapi_cli_log_message;

    server_receive_context receive_context; 
    receive_context.zserv = zserv;
    receive_context.zfd = zfd;
    receive_context.zfrom_id = zfrom_id;
    receive_context.zdata = zdata;

    SG(server_context) = (void *)&receive_context;

    if (UNEXPECTED(swoole_php_request_startup() == FAILURE)) {
        goto out;
    }

    //swoole_php_fatal_error(E_ERROR, "EEEEEEEEEEEEEEEEEEE");

    zend_file_handle file_handle;

    char *filename = "/var/www/swoole/my_index.php";

    if (zend_stream_open(filename, &file_handle) == FAILURE) {
        swTrace("execute_file, eeeeeeeeeeee");
    }


    int status = 0;

    //zend_first_try 
    /*
    zend_try {
        status = 8888;
        php_execute_script(&file_handle);

    } zend_catch {
        status = 1001;
    } zend_end_try();
    */

    php_execute_script(&file_handle);
    swNotice("execute_file, 6666, %s\n", file_handle.filename);

    swoole_php_request_shutdown();

    swNotice("execute_file, 99999999999, %d\n", status);

    //swNotice("php_output start, -----\n%s, -----end -----\n", ZSTR_VAL(output_buffer));

out:
    SG(server_context) = NULL;
    RETURN_TRUE;
}

