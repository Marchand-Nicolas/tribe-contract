// SPDX-License-Identifier: MIT

%lang starknet

// Starkware dependencies
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.uint256 import Uint256, uint256_add, uint256_lt
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import unsigned_div_rem
from starkware.starknet.common.syscalls import get_caller_address
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.signature import verify_ecdsa_signature

// Project dependencies
from openzeppelin.token.erc721.library import ERC721
from openzeppelin.access.ownable.library import Ownable

//
// Storage
//

@storage_var
func _freeId() -> (id : Uint256) {
}

@storage_var
func _public_key() -> (publicKey: felt) {
}

namespace Tribe {
    //
    // Initializer
    //

    @external
    func initializer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        public_key: felt
    ) {
        _public_key.write(public_key);
        return ();
    }

    //
    // Getters
    //

    func getFreeId{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (id : Uint256) {
        return _freeId.read();
    }

    func getPublicKey{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (publicKey: felt) {
        return _public_key.read();
    }

    func tokenURI{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(tokenId: Uint256) -> (tokenURI_len: felt, tokenURI: felt*) {
        alloc_locals;
        let (staticURI_len, staticURI) = getStaticURI();
        let (famLevel1) = uint256_lt(tokenId, Uint256(5000, 0));
        let (famLevel2) = uint256_lt(tokenId, Uint256(2000, 0));

        let level = 0 + famLevel1 + famLevel2;

        // Append .json to the static URI
        assert [staticURI + staticURI_len + 1] = 46;
        assert [staticURI + staticURI_len + 2] = 106;
        assert [staticURI + staticURI_len + 3] = 115;
        assert [staticURI + staticURI_len + 4] = 111;
        assert [staticURI + staticURI_len + 5] = 110;
        
        if (level == 0) {
            assert [staticURI + staticURI_len] = 48;
            let staticURI_len = staticURI_len + 6;
            return (tokenURI_len=staticURI_len, tokenURI=staticURI);
        }
        if (level == 1) {
            assert [staticURI + staticURI_len] = 49;
            let staticURI_len = staticURI_len + 6;
            return (tokenURI_len=staticURI_len, tokenURI=staticURI);
        }
        if (level == 2) {
            assert [staticURI + staticURI_len] = 50;
            let staticURI_len = staticURI_len + 6;
            return (tokenURI_len=staticURI_len, tokenURI=staticURI);
        }

        return (tokenURI_len=staticURI_len, tokenURI=staticURI);
    }

    //
    // Externals
    //

    func mint{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr, ecdsa_ptr: SignatureBuiltin*}(
        sig: (felt, felt),
    ) {
        let (player) = get_caller_address();

        // Get NFT id
        let (oldId) = _freeId.read();
        let (newId, _) = uint256_add(oldId, Uint256(1, 0));

        // Check if the signature is valid
        let (messageHash) = hash2{hash_ptr=pedersen_ptr}(player, 0);
        let (public_key) = _public_key.read();
        verify_ecdsa_signature(messageHash, public_key, sig[0], sig[1]);

        // Mint NFT
        ERC721._mint(player, newId);
        _freeId.write(newId);
        return ();
    }

    func setPublicKey{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(public_key : felt) {
        alloc_locals;
        Ownable.assert_only_owner();
        _public_key.write(public_key);
        return ();
    }
}

//
// Internals
//

func getStaticURI() -> (staticURI_len : felt, staticURI : felt*) {
    alloc_locals;
    let (staticURI) = alloc();
    assert [staticURI] = 104;
    assert [staticURI + 1] = 116;
    assert [staticURI + 2] = 116;
    assert [staticURI + 3] = 112;
    assert [staticURI + 4] = 58;
    assert [staticURI + 5] = 47;
    assert [staticURI + 6] = 47;
    assert [staticURI + 7] = 108;
    assert [staticURI + 8] = 111;
    assert [staticURI + 9] = 99;
    assert [staticURI + 10] = 97;
    assert [staticURI + 11] = 108;
    assert [staticURI + 12] = 104;
    assert [staticURI + 13] = 111;
    assert [staticURI + 14] = 115;
    assert [staticURI + 15] = 116;
    assert [staticURI + 16] = 58;
    assert [staticURI + 17] = 51;
    assert [staticURI + 18] = 48;
    assert [staticURI + 19] = 48;
    assert [staticURI + 20] = 48;
    assert [staticURI + 21] = 47;
    assert [staticURI + 22] = 97;
    assert [staticURI + 23] = 112;
    assert [staticURI + 24] = 105;
    assert [staticURI + 25] = 47;
    assert [staticURI + 26] = 116;
    assert [staticURI + 27] = 114;
    assert [staticURI + 28] = 105;
    assert [staticURI + 29] = 98;
    assert [staticURI + 30] = 101;
    assert [staticURI + 31] = 47;
    assert [staticURI + 32] = 110;
    assert [staticURI + 33] = 102;
    assert [staticURI + 34] = 116;
    assert [staticURI + 35] = 47;
    return (36, staticURI);
}