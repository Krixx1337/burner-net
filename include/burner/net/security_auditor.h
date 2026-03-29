#pragma once

#include "export.h"
#include "http.h"

namespace burner::net {

class BURNER_API SecurityAuditor {
public:
    static bool CheckTransportIntegrity(IHttpClient* client);
};

} // namespace burner::net
