// SPDX-License-Identifier: MIT

%lang starknet

// Starkware dependencies
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin

@contract_interface
namespace IStarknetIDNamingContract {
    func address_to_domain(address: felt) -> (domain_len: felt, domain: felt*) {
    }
}