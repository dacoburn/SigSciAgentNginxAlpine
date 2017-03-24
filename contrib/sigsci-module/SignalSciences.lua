--
-- Signal Sciences NGINX module
-- Copyright 2015-2016 Signal Sciences
-- Proprietary and Confidential
--

local mp = require "MessagePack"
local mpversion = "lua-MessagePack " .. mp._VERSION

-- string starts with http://lua-users.org/wiki/StringRecipes
local function string_starts_with (str, prefix)
  return string.sub(str, 1, string.len(prefix)) == prefix
end

-- string ends with
local function string_ends_with (str, suffix)
  return suffix == '' or string.sub(str, -string.len(suffix)) == suffix
end

local m = {}

-- config_dump() will output the k-v pairs stored in m
function m.config_dump ()
  for k, v in pairs(m) do
    local t = type(v)
    if t == "string" or t == "number" then
      ngx.log(ngx.STDERR, "key = ", k, " val = ", v)
    end
  end
end

-- simple function to help
local function istable (t)
  return type(t) == 'table'
end

-- does basics
function m.get_rdata (hin)
  return {
    AccessKeyID = "",
    ModuleVersion = m._MODULE_VERSION,
    ServerVersion = ngx.var.nginx_version,
    ServerFlavor = m._SERVER_FLAVOR,
    ServerName = ngx.var.http_host,
    Timestamp = ngx.time(),
    NowMillis = math.floor(ngx.now() * 1000),
    RemoteAddr = ngx.var.remote_addr,
    Method = ngx.var.request_method,
    Scheme = ngx.var.scheme,
    URI = ngx.var.request_uri,
    Protocol = ngx.var.server_protocol,
    TLSProtocol = ngx.var.ssl_protocol,
    TLSCipher = ngx.var.ssl_cipher,
    HeadersIn = hin,
  }
end

-- log network errors, socket connection/read/write issues
function m.network_error (...)
  if m.log_network_errors then
    ngx.log(ngx.ERR, "SIGSCI: ", ...)
  end
end

-- log internal errors -- nginx specific items, corrupted data, etc
function m.internal_error (...)
  if m.log_internal_errors then
    ngx.log(ngx.ERR, "SIGSCI: ", ...)
  end
end

-- log debug -- log internal debugging
function m.debug (...)
  if m.log_debug then
    ngx.log(ngx.ERR, "SIGSCI: DEBUG ", ...)
  end
end

-- get socket
-- http://wiki.nginx.org/HttpLuaModule#tcpsock:connect
function m.socket ()
  local ok, err
  local sock = ngx.socket.tcp()
  sock:settimeout(m.timeout)
  sock:setkeepalive(m.keepalive)
  local agenthost = m.agenthost
  local agentport = m.agentport

  if string_starts_with(agenthost, "unix:/") then
    ok, err = sock:connect(agenthost)
  else
    ok, err = sock:connect(agenthost, agentport)
  end
  if not ok then
    m.network_error("failed to connect to agent, ", err)
    return nil
  end
  return sock
end

function m.send_rpc (partial, rpc_call, payload)
  -- note `partial` is a nginx-ism and can be ignored.
  -- It occurs when a timer prematurely fires, like due
  -- to when the server is shutting down.
  if partial then
    m.internal_error "Got async partial"
  end

  local sock, rpcid, ok, err, resp, buf, mpunpack
  sock = m.socket()
  if sock == nil then
    return nil
  end

  rpcid, err = ngx.shared.sigsci_conf:incr("counter", 1)
  if rpcid == nil then
    m.internal_error("unable to make counter, ", err)
    return nil
  end
  local obj = {
    0,
    rpcid,
    rpc_call,
    {
      payload,
    },
  }

  ok, buf = pcall(mp.pack, obj)
  if not ok then
    m.internal_error("unable to create object for ", rpc_call, ", ", err)
    return nil
  end

  ok, err = sock:send(buf)
  if ok == nil then
    m.network_error("unable to send ", rpc_call, ", ", err)
    return nil
  end

  -- note msgpack library uses exceptions
  local resp_bytes_read = 0
  ok, mpunpack = pcall(
    mp.unpacker,
    -- If there is not enough data, this will be called repeatedly to get another
    -- byte until there is enough. Better would be to know how many bytes are needed
    -- and ask to receive that many.
    -- Unfortunately lua receive(n) will block waiting for exactly n or error.
    function ()
      local sbuf, e = sock:receive(1)
      if e ~= nil then
        m.network_error("error receiving response: ", e)
        return nil
      end
      resp_bytes_read = resp_bytes_read + string.len(sbuf)
      return sbuf
    end
  )
  if not ok or not mpunpack or type(mpunpack) ~= "function" then
    m.internal_error("failed to get a message pack unpacker")
    return nil
  end
  -- NOTE:
  -- This will read *any* message - maybe better to limit to array (table) as
  -- that is what we are expecting. Take a look at mp.unpacker(src) and write our own?
  ok, resp = mpunpack()
  if not ok then
    m.debug(rpc_call, " invalid response size=", resp_bytes_read)
    return nil
  end
  if table.getn(resp) ~= 4 or resp[1] ~= 1 or resp[2] ~= rpcid or resp[3] then
    m.internal_error("corrupted reply for ", rpc_call, " {", resp[1], " ", resp[2], " ", resp[3], " ", resp[4], "}")
    return nil
  end
  if resp[4] == nil then
    m.debug(rpc_call, " response result was empty: size=", resp_bytes_read, " [type=", resp[1], ", msgid=", resp[2], ", error=", resp[3], ", result=", resp[4], "]")
  else
    if type(resp[4]) == "table" then
      m.debug(rpc_call, " response: size=", resp_bytes_read, " [type=", resp[1], ", msgid=", resp[2], ", error=", resp[3], ", result=", tostring(resp[4]), "] wafresponse=", resp[4].WAFResponse, " requestid=", resp[4].RequestID)
    else
      m.debug(rpc_call, " response: size=", resp_bytes_read, " [type=", resp[1], ", msgid=", resp[2], ", error=", resp[3], ", result=", resp[4], "]")
    end
  end
  return resp[4]
end

function m.send_rpc_async (rpcname, payload)
  local ok, err = ngx.timer.at(0, m.send_rpc, rpcname, payload)
  if not ok then
    m.internal_error("failed to create timer for ", rpcname, ", ", err)
  end
end

-- is the content-length valid and reflects a small enough
-- size that we can process?
function m.valid_content_length (val, maxlen)
  if val == nil then
    return false
  end
  local len = tonumber(val)
  if len == nil then
    return false
  end
  if len < 0 then
    return false
  end
  return len <= maxlen
end

-- is this a valid method
-- we do not support some methods
--
function m.valid_method (meth)
  if meth == nil then
    return false
  end
  local lcmeth = meth:lower()
  return not (lcmeth == "options" or lcmeth == "connect")
end

-- is this a content-type we can process
--
-- note: many content-types for JSON
-- http://stackoverflow.com/questions/477816/what-is-the-correct-json-content-type
--
function m.valid_content_type (val)
  if val == nil then
    return false
  end
  val = val:lower()
  if string_starts_with(val, "application/x-www-form-urlencoded") then
    return true
  end
  if val:find "json" or val:find "javascript" then
    return true
  end
  -- https://en.wikipedia.org/wiki/XML_and_MIME
  if string_ends_with(val, "xml") then
    return true
  end
  return false
end

-- This transforms the http request headers into a form usable by SigSci
--
-- nginx headers are stored as
-- header-name = value (single string)
-- header-name = { value1, value2 } (array of string)
--
-- SigSci API expects a list of key value pairs
-- {{ header: value }, {header: value} ... }
--
function m.transform_headers (nginxheaders)
  local headers = {}
  for k, v in pairs(nginxheaders) do
    if type(v) == "string" then
      table.insert(headers, {
          k,
          v,
        })
    else
      -- it is a list
      for i = 1, #v do
        table.insert(headers, {
            k,
            v[i],
          })
      end
    end
  end
  return headers
end

-- send back we can get before content-handlers run
-- this means we send back headers and post data but not
-- status, timing and size (since they dont exist yet)
function m.prerequest (access_key_id)
  -- subrequest occur during nginx proxying or internal redirection to
  -- index pages, e.g. "/" --> "/index.html"
  -- in which case we already handled everything and can just exit out
  if ngx.is_subrequest and m.subrequest_support == false then
    if m.subrequest_support == false then
      m.debug("skipping subrequest")
      return
    end
    m.debug("handling subrequest")
  end
  -- we have some status already, ignore
  -- this happens for custom error page loads?
  if ngx.status > 0 then
    return
  end

  if not m.valid_method(ngx.var.request_method) then
    return
  end

  local hin = m.transform_headers(ngx.req.get_headers(0, true))
  local rdata = m.get_rdata(hin)

  if access_key_id ~= nil then
    rdata.AccessKeyID = access_key_id
  end

  -- sadly the header value is either a string or an array of strings
  -- this makes serialization difficult
  -- convert to list of key-value pairs

  -- get post data if content-type is right, and not too large
  local postbody = nil
  if m.valid_content_length(ngx.var.http_content_length, m.maxpost) and m.valid_content_type(ngx.var.http_content_type) then
    ngx.req.read_body()
    postbody = ngx.req.get_body_data()
  end
  rdata["PostBody"] = postbody

  local resp = m.send_rpc(false, "RPC.PreRequest", rdata)
  if resp == nil then
    return
  end

  -- Fixups for RPCv1
  --
  -- RPCv1 will include empty values in the response that in
  -- RPCv0 were not included, so these need to be fixed
  -- to support RPCv1 if the missing value is relied upon.
  -- (e.g., RequestID missing means do not run the
  -- RPC.UpdateRequest call).
  --
  -- See: https://github.com/tinylib/msgp/issues/103
  if resp.RequestID and string.len(resp.RequestID) == 0 then
    resp.RequestID = nil
  end

  -- nginx-ism
  -- sadly custom error pages do not preserve request context
  -- but... response headers are, so we keep state this way
  -- the downside is that the end-client gets an extra header.
  -- TBD on improvement here
  ngx.req.set_header("X-SigSci-RequestID", resp.RequestID)
  ngx.req.set_header("X-SigSci-AgentResponse", resp.WAFResponse)
  ngx.ctx.requestid = resp.RequestID
  ngx.ctx.agentresponse = resp.WAFResponse
  m.debug("stored context: requestid=", ngx.ctx.requestid, ", agentresponse=", ngx.ctx.agentresponse)

  -- Add any headers to the response
  -- new feature 2015-07-08
  local request_headers = resp.RequestHeaders
  if istable(request_headers) then
    for i = 1, #request_headers do
      local v = request_headers[i]
      ngx.req.set_header(v[1], v[2])
      m.debug("set additional request header: ", v[1], "=", v[2])
    end
  end

  --
  -- Allow, Block, or Allow/Fail Open
  --
  local waf_response = tonumber(resp.WAFResponse)
  if waf_response == 200 then
    -- normal case
    -- ngx.exit(200) causes strange behavior so dont do it.
    return
  end
  if waf_response == 406 then
    -- blocking case
    m.debug("blocking with status=", waf_response)
    ngx.exit(waf_response)
    return
  end

  -- unknown response, fail open
  m.internal_error("failing open, agent responded with invalid exit code ", resp.WAFResponse)
end

--
-- handles after-the-request-is-done (post-request) logic
--
function m.postrequest (access_key_id)
  if not m.valid_method(ngx.var.request_method) then
    m.debug("ignoring method=", ngx.var.request_method)
    return
  end

  -- again, for other implementation, do not use an HTTP header
  -- but some other context for saving/getting the RequestID
  -- local agentresponse = 0
  local requestid = ngx.ctx.requestid
  if requestid == nil then
    requestid = ngx.req.get_headers()['X-SigSci-RequestID']
  end
  local agentresponse = ngx.ctx.agentresponse
  if agentresponse == nil then
    agentresponse = tonumber(ngx.req.get_headers()["X-SigSci-AgentResponse"])
    m.debug("fallback to header for agentresponse=", agentresponse, " subrequest=", ngx.is_subrequest)
  end
  if agentresponse == nil then
    -- set to -2 so we know the pre- and post- request are disassociated
    agentresponse = -2
  end
  m.debug("retrieved context: requestid=", requestid, ", agentresponse=", agentresponse)

  -- http response status
  local status = ngx.status

  -- Use body_bytes_sent since
  -- * its in all nginx versions
  -- * matches what is in logs
  -- * bytes_sent is only in > 1.2 versions
  -- * see http://nginx.org/en/docs/http/ngx_http_core_module.html#var_bytes_sent
  -- ngx.var.(body_)bytes_sent comes back as a string (why?)
  -- so corerce to integer
  local bytesout = tonumber(ngx.var.body_bytes_sent)

  -- total request time in milliseconds
  local millis = math.floor(1000.0 * (ngx.now() - ngx.req.start_time()))
  if millis < 0 then
    -- can happen due to clock drift, lack of montonicity, etc
    millis = 0
  end

  --
  -- Conditionally send an update request for one or more of the
  -- following conditions:
  -- * the request has a request ID
  -- * the response size exceeds the configured maximum size
  -- * the response time exceeds the configured maximum response time
  -- The update returned to the agent simply updates the stored metadata.
  --
  if requestid then
    local rdata = {
      RequestID = requestid,
      ResponseCode = status,
      ResponseSize = bytesout,
      ResponseMillis = millis,
      HeadersOut = m.transform_headers(ngx.resp.get_headers(0, true)),
    }

    if access_key_id ~= nil then
      rdata.AccessKeyID = access_key_id
    end

    -- just update status, time, size, etc
    m.send_rpc_async("RPC.UpdateRequest", rdata)
    return
  end

  --
  -- We do not have a request id. The original request looked fine
  -- TODO or if time is too long, or if size is too large
  --
  if ngx.status >= 300 or bytesout > m.maxsize or millis > m.maxtime then
    -- just update status, time, size, etc
    -- copy full request, minus post data and headers locally
    -- data will not exist after timer
    local hin = m.transform_headers(ngx.req.get_headers(0, true))
    local hout = m.transform_headers(ngx.resp.get_headers(0, true))
    local rdata = m.get_rdata(hin)

    if access_key_id ~= nil then
      rdata.AccessKeyID = access_key_id
    end

    rdata.HeadersOut = hout
    rdata.WAFResponse = agentresponse
    rdata.ResponseCode = status
    rdata.ResponseSize = bytesout
    rdata.ResponseMillis = millis

    m.send_rpc_async("RPC.PostRequest", rdata)
  end
end

--
-- initialization and constants
--
local ngx_lua_version = "dev"
if ngx then
  -- if not in testing environment
  ngx.shared.sigsci_conf:set("counter", 0)
  ngx_lua_version = tostring(ngx.config.ngx_lua_version)
end

-- module defaults
m.timeout = 100
m.keepalive = 10000
m.agenthost = "unix:/var/run/sigsci.sock"
m.agentport = 12345
m.maxpost = 300000
m.maxtime = 1000
m.maxsize = 512 * 1024
m.subrequest_support = false
m.log_network_errors = false
m.log_internal_errors = true
m.log_debug = false

if jit then
  m._SERVER_FLAVOR = ngx_lua_version .. ", lua=" .. jit.version
else
  m._SERVER_FLAVOR = ngx_lua_version .. ", lua=" .. _VERSION
  m.internal_error("WARNING: The lua being used is not luajit and may not be supported!!! ", m._SERVER_FLAVOR)
end

m._VERSION = "1.1.7"
m._BUILD_NUMBER = "476"
m._MODULE_VERSION = m._VERSION

m._DESCRIPTION = "sigsci-module-nginx : Signal Sciences nginx integration module"
m._COPYRIGHT = "Copyright (c) 2016 Signal Sciences Corp. Proprietary and Confidential."

if ngx then
  ngx.log(ngx.NOTICE, "SIGSCI=" .. m._MODULE_VERSION .. ", ngx_lua=" .. m._SERVER_FLAVOR .. ", msgpack=" .. mpversion)
end
return m

-- vim: tabstop=2 expandtab shiftwidth=2 softtabstop=2
