/*
 * Copyright 2010, Nikhil Marathe <nsm.nikhil@gmail.com> All rights reserved.
 * See LICENSE for details
 */

#ifndef SASLJS_H
#define SASLJS_H

#include <gsasl.h>

#include <v8.h>
#include <node.h>
#include <node/node_object_wrap.h>

namespace sasljs {
class ServerConnection : public node::ObjectWrap
{
  public:
    static void
    Initialize ( v8::Handle<v8::Object> target );

  protected:
    static v8::Handle<v8::Value>
    New (const v8::Arguments& args);

    static v8::Handle<v8::Value> GetMechanisms( const v8::Arguments& args );
    static v8::Handle<v8::Value> Start( const v8::Arguments &args );
    static v8::Handle<v8::Value> Step( const v8::Arguments &args );

    ServerConnection( const char *service, const char *realm );
    ~ServerConnection();

  private:
    Gsasl_session *m_session;
};

static Gsasl *ctx;
}

#endif
