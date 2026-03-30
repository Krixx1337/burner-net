#pragma once

#include "export.h"
#include "http.h"

namespace burner::net {

class BURNER_API SecurityAuditor {
public:
    static bool CheckTransportIntegrity(IHttpClient* client);
    static bool CheckTransportIntegrity(IHttpClient* client, const ISecurityPolicy* policy);
};

} // namespace burner::net
