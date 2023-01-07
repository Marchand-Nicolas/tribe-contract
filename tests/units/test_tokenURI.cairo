// SPDX-License-Identifier: MIT

%lang starknet

// Starkware dependencies
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256

// Local dependencies
from src.library import Tribe
@external
func test_getURI{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}() {
    let (URI_len, URI) = Tribe.tokenURI(Uint256(1, 0));

    assert [URI] = 104;
    assert [URI + 1] = 116;
    assert [URI + 2] = 116;
    assert [URI + 3] = 112;
    assert [URI + 4] = 58;
    assert [URI + 5] = 47;
    assert [URI + 6] = 47;
    assert [URI + 7] = 108;
    assert [URI + 8] = 111;
    assert [URI + 9] = 99;
    assert [URI + 10] = 97;
    assert [URI + 11] = 108;
    assert [URI + 12] = 104;


    return ();
}
