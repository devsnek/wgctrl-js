#include <napi.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

extern "C" {
#include <wireguard.h>
}

Napi::Value GetDevices(const Napi::CallbackInfo& info) {
  auto env = info.Env();

  char* device_names = wg_list_device_names();
  if (!device_names) {
    return env.Null();
  }

  auto devices = Napi::Array::New(env);

  const char* device_name;
  size_t len;
  uint32_t index = 0;
  wg_for_each_device_name(device_names, device_name, len) {
    devices[index] = Napi::String::New(env, device_name, len);
    index += 1;
  }

  free(device_names);

  return devices;
}

Napi::Value KeyToJS(Napi::Env env, const wg_key& key) {
  if (wg_key_is_zero(key)) {
    return env.Null();
  }
  wg_key_b64_string string;
  wg_key_to_base64(string, key);
  return Napi::String::New(env, string);
}

bool JSToKey(Napi::Env env, const Napi::Value& js, wg_key key) {
  if (!js.IsString()) {
    NAPI_THROW(Napi::Error::New(env, "key must be a base64 string"), {});
  }
  std::string skey = js.As<Napi::String>();
  if (wg_key_from_base64(key, skey.c_str()) != 0) {
    NAPI_THROW(Napi::Error::New(env, "key must be a base64 string"), {});
  }
  return true;
}

Napi::Value GetDevice(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  std::string name = info[0].As<Napi::String>();

  wg_device* device;
  if (wg_get_device(&device, name.c_str()) != 0) {
    NAPI_THROW(Napi::Error::New(env, strerror(errno)), {});
  }

  auto js_device = Napi::Object::New(env);
  js_device["name"] = Napi::String::New(env, device->name);
  js_device["ifindex"] = Napi::Number::New(env, device->ifindex);
  js_device["flags"] = Napi::Number::New(env, device->flags);
  js_device["publicKey"] = KeyToJS(env, device->public_key);
  js_device["privateKey"] = KeyToJS(env, device->private_key);
  js_device["fwmark"] = Napi::Number::New(env, device->fwmark);
  js_device["listenPort"] = Napi::Number::New(env, device->listen_port);

  auto peers = Napi::Array::New(env);
  js_device["peers"] = peers;

  wg_peer* peer;
  uint32_t index = 0;
  wg_for_each_peer(device, peer) {
    auto js_peer = Napi::Object::New(env);

    js_peer["flags"] = Napi::Number::New(env, peer->flags);
    js_peer["publicKey"] = KeyToJS(env, peer->public_key);
    js_peer["presharedKey"] = KeyToJS(env, peer->preshared_key);

    {
      char buf[INET_ADDRSTRLEN];
      char buf6[INET6_ADDRSTRLEN];
      switch (peer->endpoint.addr.sa_family) {
        case AF_INET: {
          if (inet_ntop(AF_INET, &peer->endpoint.addr4.sin_addr.s_addr, buf, sizeof(buf)) == nullptr) {
            NAPI_THROW(Napi::Error::New(env, strerror(errno)), {});
          }
          std::string buf_s{buf};
          buf_s += ":";
          buf_s += std::to_string(peer->endpoint.addr4.sin_port);
          js_peer["endpoint"] = Napi::String::New(env, buf_s);
          break;
        }
        case AF_INET6: {
          if (inet_ntop(AF_INET6, &peer->endpoint.addr6.sin6_addr.s6_addr, buf6, sizeof(buf6)) == nullptr) {
            NAPI_THROW(Napi::Error::New(env, strerror(errno)), {});
          }
          std::string buf_s{"["};
          buf_s += buf6;
          buf_s += "]:";
          buf_s += std::to_string(peer->endpoint.addr6.sin6_port);
          js_peer["endpoint"] = Napi::String::New(env, buf_s);
          break;
        }
        default:
          NAPI_THROW(Napi::TypeError::New(env, "Invalid family"), {});
      }
    }

    {
      auto duration = std::chrono::seconds{peer->last_handshake_time.tv_sec} +
                      std::chrono::nanoseconds{peer->last_handshake_time.tv_nsec};
      auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
      js_peer["lastHandhakeTime"] = Napi::BigInt::New(env, ns.count());
    }

    js_peer["rxBytes"] = Napi::BigInt::New(env, peer->rx_bytes);
    js_peer["txBytes"] = Napi::BigInt::New(env, peer->tx_bytes);
    js_peer["persistentKeepaliveInterval"] =
      Napi::Number::New(env, peer->persistent_keepalive_interval);

    auto allowed_ips = Napi::Array::New(env);
    js_peer["allowedIPs"] = allowed_ips;

    wg_allowedip* allowedip;
    uint32_t ip_index = 0;
    wg_for_each_allowedip(peer, allowedip) {
      char buf[INET_ADDRSTRLEN];
      char buf6[INET6_ADDRSTRLEN];

      switch (allowedip->family) {
        case AF_INET: {
          if (inet_ntop(AF_INET, &allowedip->ip4, buf, sizeof(buf)) == nullptr) {
            NAPI_THROW(Napi::Error::New(env, strerror(errno)), {});
          }
          std::string buf_s{buf};
          buf_s += "/";
          buf_s += std::to_string(allowedip->cidr);
          allowed_ips[ip_index] = Napi::String::New(env, buf_s);
          ip_index += 1;
          break;
        }
        case AF_INET6: {
          if (inet_ntop(AF_INET6, &allowedip->ip6, buf6, sizeof(buf6)) == nullptr) {
            NAPI_THROW(Napi::Error::New(env, strerror(errno)), {});
          }
          std::string buf_s{buf6};
          buf_s += "/";
          buf_s += std::to_string(allowedip->cidr);
          allowed_ips[ip_index] = Napi::String::New(env, buf_s);
          ip_index += 1;
          break;
        }
        default:
          NAPI_THROW(Napi::TypeError::New(env, "Invalid family"), {});
      }
    }

    peers[index] = js_peer;
    index += 1;
  }

  free(device);

  return js_device;
}

Napi::Value SetDevice(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  auto js_device = info[0].As<Napi::Object>();
  wg_device* device = new wg_device{};

  {
    std::string name = js_device.Get("name").As<Napi::String>();
    memcpy(device->name, name.c_str(), sizeof(device->name));
  }
  device->ifindex = js_device.Get("ifindex").As<Napi::Number>();
  device->flags = static_cast<wg_device_flags>(js_device.Get("flags").As<Napi::Number>().Uint32Value());
  if (!JSToKey(env, js_device["publicKey"], device->public_key)) {
    return {};
  }
  if (!JSToKey(env, js_device["privateKey"], device->private_key)) {
    return {};
  }
  device->fwmark = js_device.Get("fwmark").As<Napi::Number>().Uint32Value();
  device->listen_port = js_device.Get("listenPort").As<Napi::Number>().Uint32Value();

  {
    auto js_peers = js_device.Get("peers").As<Napi::Array>();
    uint32_t length = js_peers.Length();
    for (uint32_t i = 0; i < length; i += 1) {
      auto js_peer = js_peers.Get(i).As<Napi::Object>();
      wg_peer* peer = new wg_peer{};
      peer->next_peer = device->first_peer;
      peer->flags = static_cast<wg_peer_flags>(js_peer.Get("flags").As<Napi::Number>().Uint32Value());
      if (!JSToKey(env, js_peer["publicKey"], peer->public_key)) {
        return {};
      }
      if (!JSToKey(env, js_peer["presharedKey"], peer->preshared_key)) {
        return {};
      }
      {
        std::string endpoint_s = js_peer.Get("endpoint").As<Napi::String>();
        auto v6 = endpoint_s.rfind("[", 0) == 0;
        if (v6) {
          auto pos = endpoint_s.find_first_of("]:");
          auto ip = endpoint_s.substr(1, pos);
          if (inet_pton(AF_INET6, ip.c_str(), &peer->endpoint.addr6.sin6_addr.s6_addr) != 1) {
            NAPI_THROW(Napi::TypeError::New(env, "Invalid IPv6 address"), {});
          }
          auto port = endpoint_s.substr(pos + 1);
          peer->endpoint.addr4.sin_port = stoi(port);
        } else {
          auto pos = endpoint_s.find_first_of(":");
          auto ip = endpoint_s.substr(0, pos);
          if (inet_pton(AF_INET, ip.c_str(), &peer->endpoint.addr4.sin_addr.s_addr) != 1) {
            NAPI_THROW(Napi::TypeError::New(env, "Invalid IPv4 address"), {});
          }
          auto port = endpoint_s.substr(pos + 1);
          peer->endpoint.addr6.sin6_port = stoi(port);
        }
      }
      peer->persistent_keepalive_interval = js_peer.Get("persistentKeepaliveInterval").As<Napi::Number>().Uint32Value();
      {
        auto allowed_ips = js_peer.Get("allowedIPs").As<Napi::Array>();
        uint32_t length = allowed_ips.Length();
        for (uint32_t i = 0; i < length; i += 1) {
          std::string allowedip_s = allowed_ips.Get(i).As<Napi::String>();
          auto allowedip = new wg_allowedip{};
          allowedip->next_allowedip = peer->first_allowedip;
          auto v6 = allowedip_s.rfind(":", 0) == 0;
          auto pos = allowedip_s.find_first_of("/");
          auto ip = allowedip_s.substr(0, pos);
          auto cidr = allowedip_s.substr(pos + 1);
          if (v6) {
            allowedip->family = AF_INET6;
            if (inet_pton(AF_INET, ip.c_str(), &allowedip->ip6) != 1) {
              NAPI_THROW(Napi::TypeError::New(env, "Invalid IPv6 address"), {});
            }
          } else {
            allowedip->family = AF_INET;
            if (inet_pton(AF_INET, ip.c_str(), &allowedip->ip4) != 1) {
              NAPI_THROW(Napi::TypeError::New(env, "Invalid IPv4 address"), {});
            }
          }
          allowedip->cidr = stoi(cidr);
          peer->first_allowedip = allowedip;
          if (peer->last_allowedip == nullptr) {
            peer->last_allowedip = allowedip;
          }
        }
      }
      device->first_peer = peer;
      if (device->last_peer == nullptr) {
        device->last_peer = peer;
      }
    }
  }

  int ret = wg_set_device(device);
  wg_free_device(device);
  if (ret != 0) {
    NAPI_THROW(Napi::Error::New(info.Env(), strerror(errno)), {});
  }

  return info.Env().Null();
}

Napi::Value AddDevice(const Napi::CallbackInfo& info) {
  std::string name = info[0].As<Napi::String>();
  if (wg_add_device(name.c_str()) != 0) {
    NAPI_THROW(Napi::Error::New(info.Env(), strerror(errno)), {});
  }
  return info.Env().Null();
}

Napi::Value DeleteDevice(const Napi::CallbackInfo& info) {
  std::string name = info[0].As<Napi::String>();
  if (wg_del_device(name.c_str()) != 0) {
    NAPI_THROW(Napi::Error::New(info.Env(), strerror(errno)), {});
  }
  return info.Env().Null();
}

Napi::Value GeneratePublicKey(const Napi::CallbackInfo& info) {
  wg_key private_key;
  if (!JSToKey(info.Env(), info[0], private_key)) {
    return {};
  }
  wg_key public_key;
  wg_generate_public_key(public_key, private_key);
  return KeyToJS(info.Env(), public_key);
}

Napi::Value GeneratePrivateKey(const Napi::CallbackInfo& info) {
  wg_key key;
  wg_generate_private_key(key);
  return KeyToJS(info.Env(), key);
}

Napi::Value GeneratePresharedKey(const Napi::CallbackInfo& info) {
  wg_key key;
  wg_generate_preshared_key(key);
  return KeyToJS(info.Env(), key);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports["getDevices"] = Napi::Function::New(env, GetDevices);
  exports["getDevice"] = Napi::Function::New(env, GetDevice);
  exports["addDevice"] = Napi::Function::New(env, AddDevice);
  exports["deleteDevice"] = Napi::Function::New(env, DeleteDevice);
  exports["generatePublicKey"] = Napi::Function::New(env, GeneratePublicKey);
  exports["generatePrivateKey"] = Napi::Function::New(env, GeneratePrivateKey);
  exports["generatePresharedKey"] = Napi::Function::New(env, GeneratePresharedKey);

  return exports;
}

NODE_API_MODULE(addon, Init);
