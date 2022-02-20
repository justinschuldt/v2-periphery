pragma solidity =0.6.6;

import '@uniswap/v2-core/contracts/interfaces/IUniswapV2Factory.sol';
import '@uniswap/lib/contracts/libraries/TransferHelper.sol';

import './interfaces/IUniswapV2Router02.sol';
import './libraries/UniswapV2Library.sol';
import './libraries/SafeMath.sol';
import './interfaces/IERC20.sol';
import './interfaces/IWETH.sol';

contract UniswapV2Router02 is IUniswapV2Router02 {
    using SafeMath for uint;

    address public immutable override factory;
    address public immutable override WETH;

    modifier ensure(uint deadline) {
        require(deadline >= block.timestamp, 'UniswapV2Router: EXPIRED');
        _;
    }

    constructor(address _factory, address _WETH) public {
        factory = _factory;
        WETH = _WETH;
    }

    receive() external payable {
        assert(msg.sender == WETH); // only accept ETH via fallback from the WETH contract
    }


pragma solidity ^0.6.4;

contract Verifier {
    // Preset 2048 bit mod
    bytes constant MODULUS = hex"C7970CEEDCC3B0754490201A7AA613CD73911081C790F5F1A8726F463550BB5B7FF0DB8E1EA1189EC72F93D1650011BD721AEEACC2ACDE32A04107F0648C2813A31F5B0B7765FF8B44B4B6FFC93384B646EB09C7CF5E8592D40EA33C80039F35B4F14A04B51F7BFD781BE4D1673164BA8EB991C2C4D730BBBE35F592BDEF524AF7E8DAEFD26C66FC02C479AF89D64D373F442709439DE66CEB955F3EA37D5159F6135809F85334B5CB1813ADDC80CD05609F10AC6A95AD65872C909525BDAD32BC729592642920F24C61DC5B3C3B7923E56B16A4D9D373D8721F24A3FC0F1B3131F55615172866BCCC30F95054C824E733A5EB6817F7BC16399D48C6361CC7E5";
    bytes constant HALF_MOD = hex"63CB86776E61D83AA248100D3D5309E6B9C88840E3C87AF8D43937A31AA85DADBFF86DC70F508C4F6397C9E8B28008DEB90D775661566F19502083F832461409D18FAD85BBB2FFC5A25A5B7FE499C25B237584E3E7AF42C96A07519E4001CF9ADA78A5025A8FBDFEBC0DF268B398B25D475CC8E1626B985DDF1AFAC95EF7A9257BF46D77E936337E01623CD7C4EB269B9FA21384A1CEF33675CAAF9F51BEA8ACFB09AC04FC299A5AE58C09D6EE406682B04F8856354AD6B2C396484A92DED6995E394AC9321490792630EE2D9E1DBC91F2B58B526CE9B9EC390F9251FE078D9898FAAB0A8B94335E66187CA82A64127399D2F5B40BFBDE0B1CCEA4631B0E63F2";

    // Version of VDF verification which uses more calldata
    function verify_vdf_proof(bytes32 input_random, bytes memory y, bytes memory pi, uint256 iterations, uint256 prime) public view {
        // Check that y is a group member
        require(group_member(y), "Y improperly formatted");
        require(group_member(pi), "Pi improperly formatted");
        check_hash_to_prime(input_random, y, prime);
        
        // No need to cast this into the group because the size will always be small.
        uint256 r = expmod(2, iterations, prime);

        bytes memory part_1 = bignum_expmod(pi, prime, MODULUS);
        part_1 = trim(part_1);
        bytes memory part_2 = bignum_expmod(bytes_to_big_num(input_random), r, MODULUS);
        part_2 = trim(part_2);
        // Gives us four times what we want
        bytes memory proposed_y = almost_mulmod(part_1, part_2, MODULUS);
        proposed_y = trim(proposed_y);
        // So we compare to four times the y
        bytes memory almost_y = almost_mulmod(y, hex"01", MODULUS);
        almost_y = trim(almost_y);
        
        require(big_eq(proposed_y, almost_y), "VDF proof verification failed");
    }

    // This function hard casts a number which must be less than MODULUS into a RSA group member
    function group_cast(bytes memory candidate)  internal view {
        if (!group_member(candidate)) {
            candidate = big_sub(candidate, HALF_MOD);
        }
    }

    // Returns true if the group member is less than half the RSA group mod
    // NOTE - Will trim leading zeros from the candidate
    function group_member(bytes memory candidate) internal pure returns(bool) {
        candidate = trim(candidate);
        return lte(candidate, HALF_MOD);
    }

    // This trim function removes leading zeros don't contain information in our big endian format.
    function trim(bytes memory data) internal pure returns(bytes memory) {
        uint256 msb = 0;
        while (data[msb] == 0) {
            msb ++;
            if (msb == data.length) {
                return hex"";
            }
        }
        
        if (msb > 0) {
            // We don't want to copy data around, so we do the following assembly manipulation:
            // Move the data pointer forward by msb, then store in the length slot (current length - msb)
            assembly {
                let current_len := mload(data)
                data := add(data, msb)
                mstore(data, sub(current_len, msb))
            }
        }
        return data;
    }
    
    // Casts a bytes32 value into bytes memory string
    function bytes_to_big_num(bytes32 data) internal pure returns(bytes memory ptr) {

        assembly {
            ptr := mload(0x40)
            mstore(ptr, 0x20)
            mstore(add(ptr, 0x20), data)
            // Pesimestic update to free memory pointer
            mstore(0x40, add(mload(0x40), 0x40))
        }

        // Removes any zeros which aren't needed
        ptr = trim(ptr);
    }

    // This function returns (4ab) % mod for big numbs
    function almost_mulmod(bytes memory a, bytes memory b, bytes memory mod) internal view returns(bytes memory c) {
        bytes memory part1 = bignum_expmod(modular_add(a, b), 2, mod);
        bytes memory part2 = bignum_expmod(modular_sub(a, b), 2, mod);
        // Returns (a+b)^2 - (a-b)^2 = 4ab
        return modular_sub(part1, part2);
    }

    // Uses the mod const in the contract and assumes that a < Mod, b < Mod
    // Ie that the inputs are already modular group memembers.
    function modular_add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        bytes memory result = big_add(a, b);
        if (lte(result, MODULUS) && !big_eq(result, MODULUS)) {
            return result;
        } else {
            // NOTE a + b where a < MOD, b < MOD => a+b < 2 MOD => a+b % mod = a+b - MOD
            return big_sub(result, MODULUS);
        }
    }

    function modular_sub(bytes memory a, bytes memory b) internal view returns(bytes memory) {
        if (lte(b, a)) {
            return big_sub(a, b);
        } else {
            return (big_sub(MODULUS, big_sub(b, a)));
        }
    }

    // Returns (a <= b);
    // Requires trimmed inputs
    function lte(bytes memory a, bytes memory b) internal pure returns (bool) {
        if (a.length < b.length) {
            return true;
        }
        if (a.length > b.length) {
            return false;
        }

        for (uint i = 0; i < a.length; i++) {
            // If the current byte of a is less than that of b then a is less than b
            if (a[i] < b[i]) {
                return true;
            }
            // If it's strictly more then b is greater
            if (a[i] > b[i]) {
                return false;
            }
        }
        // We hit this condition if a == b
        return true;
    }

    uint mask = 0x00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    // This big add function has performance on the order of the limb version, but
    // it worse because it chunks out limbs for as long as it can from the bytes and
    // when there isn't enough data for a 31 bit limb in either a or b it goes byte by byte
    // Preformance degrades to byte by byte when adding a full 2048 bit number to a small number.
    // It is best when adding two full sized 2048 bit numbers
    function big_add(bytes memory a, bytes memory b) internal view returns(bytes memory) {
        // a + b < 2*max(a, b) so this can't have more bytes than the max length + 1
        bytes memory c = new bytes(max(a.length, b.length) + 1);
        // The index from the back of the data arrays [since this is Big endian]
        uint current_index = 0;
        uint8 carry = 0;
        // This loop grabs large numbers from the byte array for as long as we can
        while (a.length - current_index > 31 && b.length - current_index > 31) {
            // Will have 31 bytes of a's next digits
            uint a_data;
            // Will have 31 bytes of b's next digits
            uint b_data;
            assembly {
                //Load from memory at the data location of a + a.length - (current_index - 32)
                // This can load a bit of extra data which will be masked off.
                a_data := mload(add(add(a, 0x20), sub(mload(a), add(current_index, 32))))
                //Load from memory at the data location of b + b.length - (current_index - 32)
                b_data := mload(add(add(b, 0x20), sub(mload(b), add(current_index, 32))))
            }
            a_data = a_data & mask;
            b_data = b_data & mask;
            // Add the input data and the carried data.
            // TODO - Limb overflow checks the implementation may break on a+b > 2^31*8 with carry != 0
            uint sum =  a_data + b_data + carry;
            // Coerce solidity into giving me the first byte as a small number;
            carry = uint8(bytes1(bytes32(sum)));
            // Slice off the carry
            sum = sum & mask;
            // Store the sum-ed digits
            assembly {
                mstore(add(add(c, 0x20), sub(mload(c), add(current_index, 32))), sum)
            }
            current_index += 31;
        }
        
        // Now we go byte by byte
        while (current_index < max(a.length, b.length)) {
            uint16 a_data;
            if (current_index < a.length) {
                a_data = uint16(uint8(a[a.length - current_index-1]));
            } else {
                a_data = 0;
            }
            
            uint16 b_data;
            if (current_index < b.length) {
                b_data = uint16(uint8(b[b.length - current_index-1]));
            } else {
                b_data = 0;
            }

            uint16 sum = a_data + b_data + carry;
            c[c.length - current_index-1] = bytes1(uint8(sum));
            carry = uint8(sum >> 8);
            current_index++;
        }
        c[0] = bytes1(carry);
        c = trim(c);
        return c;
    }

    function max(uint a, uint b) internal pure returns (uint) {
        return a > b ? a : b;
    }

    // This extra digit allows us to preform the subtraction without underflow
    uint max_set_digit = 0x0100000000000000000000000000000000000000000000000000000000000000;

    // This function reverts on underflows, and expects trimed data
    function big_sub(bytes memory a, bytes memory b) internal view returns(bytes memory) {
        require(a.length >= b.length, "Subtraction underflow");
        // a - b =< a so this can't have more bytes than a
        bytes memory c = new bytes(a.length);
        // The index from the back of the data arrays [since this is Big endian]
        uint current_index = 0;
        uint8 carry = 0;
        // This loop grabs large numbers from the byte array for as long as we can
        while (a.length - current_index > 31 && b.length - current_index > 31) {
            // Will have 31 bytes of a's next digits
            uint a_data;
            // Will have 31 bytes of b's next digits
            uint b_data;
            assembly {
                //Load from memory at the data location of a + a.length - (current_index - 32)
                // This can load a bit of extra data which will be masked off.
                a_data := mload(add(add(a, 0x20), sub(mload(a), add(current_index, 32))))
                //Load from memory at the data location of b + b.length - (current_index - 32)
                b_data := mload(add(add(b, 0x20), sub(mload(b), add(current_index, 32))))
            }
            a_data = a_data & mask;
            b_data = b_data & mask;
            uint sub_digit;
            // We now check if we can sub b_data + carry from a_data
            if (a_data >= b_data + carry) {
                sub_digit = a_data - (b_data + carry);
                carry = 0;
            } else {
                // If not we add a one digit at the top of a, then sub
                sub_digit = (a_data + max_set_digit) - (b_data + carry);
                carry = 1;
            }

            // Store the sum-ed digits
            assembly {
                mstore(add(add(c, 0x20), sub(mload(c), add(current_index, 32))), sub_digit)
            }
            current_index += 31;
        }
        
        // Now we go byte by byte through the bytes of a
        while (current_index < a.length) {
            uint16 a_data = uint16(uint8(a[a.length - current_index-1]));
            
            // Since tighly packed this may implicly be zero without being set
            uint16 b_data;
            if (current_index < b.length) {
                b_data = uint16(uint8(b[b.length - current_index-1]));
            } else {
                b_data = 0;
            }

            uint sub_digit;
            // We now check if we can sub b_data + carry from a_data
            if (a_data >= b_data + carry) {
                sub_digit = a_data - (b_data + carry);
                carry = 0;
            } else {
                // If not we add a one digit at the top of a, then sub
                sub_digit = (a_data + 0x0100) - (b_data + carry);
                carry = 1;
            }

            c[c.length - current_index-1] = bytes1(uint8(sub_digit));
            current_index++;
        }
        require(carry == 0, "Underflow error");
        c = trim(c);
        return c;
    }
    
    // Cheap big number comparsion using hash
    // TODO - Verify that this is actually cheaper for the bitsize in question
    function big_eq(bytes memory a, bytes memory b) internal pure returns(bool) {
        return keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }
    
    // Thanks to Dankrad Feist for the bignum exp, hash to prime, and prime test.
    // https://github.com/dankrad/rsa-bounty/blob/master/contract/rsa_bounty.sol
    
    uint256 constant prime_mask = 0x7fff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_f000;
        
    // This function checks if:
    // (1) If h = Hash(input_random, y)
    //    (1a) That h is equal to prime except at the 12 last bits and the most signifigant bit.
    //    (1b) that the prime has msb 1
    // (2) That prime candidate passes the miller rabbin test with 28 round of randomly derived bases [derived from y]
    // TODO - consider adding blockhash to the random base derivation for extra security.
    function check_hash_to_prime(bytes32 input_random, bytes memory y, uint256 prime) public view {
        // Check p is correct result for hash-to-prime
        require(prime & prime_mask == uint(sha256(abi.encodePacked(input_random, y))) & prime_mask);
        require(prime > (1 << 255));
        require(miller_rabin_test(prime));
    }
    
    // Expmod for small operands
    function expmod(uint256 base, uint256 e, uint256 m) public view returns (uint o) {
        assembly {
            // Get free memory pointer
            let p := mload(0x40)
            // Store parameters for the Expmod (0x05) precompile
            mstore(p, 0x20)             // Length of Base
            mstore(add(p, 0x20), 0x20)  // Length of Exponent
            mstore(add(p, 0x40), 0x20)  // Length of Modulus
            mstore(add(p, 0x60), base)  // Base
            mstore(add(p, 0x80), e)     // Exponent
            mstore(add(p, 0xa0), m)     // Modulus

            // Call 0x05 (EXPMOD) precompile
            if iszero(staticcall(sub(gas(), 2000), 0x05, p, 0xc0, p, 0x20)) {
                revert(0, 0)
            }
            o := mload(p)
        }
    }
    
    // Expmod for bignum operands (encoded as bytes, only base and modulus)
    function bignum_expmod(bytes memory base, uint256 e, bytes memory m) public view returns (bytes memory o) {
        assembly {
            // Get free memory pointer
            let p := mload(0x40)

            // Get base length in bytes
            let bl := mload(base)
            // Get modulus length in bytes
            let ml := mload(m)

            // Store parameters for the Expmod (0x05) precompile
            mstore(p, bl)               // Length of Base
            mstore(add(p, 0x20), 0x20)  // Length of Exponent
            mstore(add(p, 0x40), ml)    // Length of Modulus
            // Use Identity (0x04) precompile to memcpy the base
            if iszero(staticcall(10000, 0x04, add(base, 0x20), bl, add(p, 0x60), bl)) {
                revert(0, 0)
            }
            mstore(add(p, add(0x60, bl)), e) // Exponent
            // Use Identity (0x04) precompile to memcpy the modulus
            if iszero(staticcall(10000, 0x04, add(m, 0x20), ml, add(add(p, 0x80), bl), ml)) {
                revert(0, 0)
            }
            
            // Call 0x05 (EXPMOD) precompile
            if iszero(staticcall(sub(gas(), 2000), 0x05, p, add(add(0x80, bl), ml), add(p, 0x20), ml)) {
                revert(0, 0)
            }

            // Update free memory pointer
            mstore(0x40, add(add(p, ml), 0x20))

            // Store correct bytelength at p. This means that with the output
            // of the Expmod precompile (which is stored as p + 0x20)
            // there is now a bytes array at location p
            mstore(p, ml)

            // Return p
            o := p
        }
    }

    uint256 constant miller_rabin_checks = 28;

    // Use the Miller-Rabin test to check whether n>3, odd is a prime
    function miller_rabin_test(uint256 n) public view returns (bool) {
        require(n > 3);
        require(n & 0x1 == 1);
        uint256 d = n - 1;
        uint256 r = 0;
        while(d & 0x1 == 0) {
            d /= 2;
            r += 1;
        }
        for(uint256 i = 0; i < miller_rabin_checks; i++) {
            // pick a pseudo-random integer a in the range [2, n − 2]
            uint256 a = (uint256(sha256(abi.encodePacked(n, i))) % (n - 3)) + 2;
            uint256 x = expmod(a, d, n);
            if(x == 1 || x == n - 1) {
                continue;
            }
            bool check_passed = false;
            for(uint256 j = 1; j < r; j++) {
                x = mulmod(x, x, n);
                if(x == n - 1) {
                    check_passed = true;
                    break;
                }
            }
            if(!check_passed) {
                return false;
            }
        }
        return true;
    }
}
    // **** ADD LIQUIDITY ****
    function _addLiquidity(
        address tokenA,
        address tokenB,
        uint amountADesired,
        uint amountBDesired,
        uint amountAMin,
        uint amountBMin
    ) internal virtual returns (uint amountA, uint amountB) {
        // create the pair if it doesn't exist yet
        if (IUniswapV2Factory(factory).getPair(tokenA, tokenB) == address(0)) {
            IUniswapV2Factory(factory).createPair(tokenA, tokenB);
        }
        (uint reserveA, uint reserveB) = UniswapV2Library.getReserves(factory, tokenA, tokenB);
        if (reserveA == 0 && reserveB == 0) {
            (amountA, amountB) = (amountADesired, amountBDesired);
        } else {
            uint amountBOptimal = UniswapV2Library.quote(amountADesired, reserveA, reserveB);
            if (amountBOptimal <= amountBDesired) {
                require(amountBOptimal >= amountBMin, 'UniswapV2Router: INSUFFICIENT_B_AMOUNT');
                (amountA, amountB) = (amountADesired, amountBOptimal);
            } else {
                uint amountAOptimal = UniswapV2Library.quote(amountBDesired, reserveB, reserveA);
                assert(amountAOptimal <= amountADesired);
                require(amountAOptimal >= amountAMin, 'UniswapV2Router: INSUFFICIENT_A_AMOUNT');
                (amountA, amountB) = (amountAOptimal, amountBDesired);
            }
        }
    }
    function addLiquidity(
        address tokenA,
        address tokenB,
        uint amountADesired,
        uint amountBDesired,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external virtual override ensure(deadline) returns (uint amountA, uint amountB, uint liquidity) {
        (amountA, amountB) = _addLiquidity(tokenA, tokenB, amountADesired, amountBDesired, amountAMin, amountBMin);
        address pair = UniswapV2Library.pairFor(factory, tokenA, tokenB);
        TransferHelper.safeTransferFrom(tokenA, msg.sender, pair, amountA);
        TransferHelper.safeTransferFrom(tokenB, msg.sender, pair, amountB);
        liquidity = IUniswapV2Pair(pair).mint(to);
    }
    function addLiquidityETH(
        address token,
        uint amountTokenDesired,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external virtual override payable ensure(deadline) returns (uint amountToken, uint amountETH, uint liquidity) {
        (amountToken, amountETH) = _addLiquidity(
            token,
            WETH,
            amountTokenDesired,
            msg.value,
            amountTokenMin,
            amountETHMin
        );
        address pair = UniswapV2Library.pairFor(factory, token, WETH);
        TransferHelper.safeTransferFrom(token, msg.sender, pair, amountToken);
        IWETH(WETH).deposit{value: amountETH}();
        assert(IWETH(WETH).transfer(pair, amountETH));
        liquidity = IUniswapV2Pair(pair).mint(to);
        // refund dust eth, if any
        if (msg.value > amountETH) TransferHelper.safeTransferETH(msg.sender, msg.value - amountETH);
    }

    // **** REMOVE LIQUIDITY ****
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) public virtual override ensure(deadline) returns (uint amountA, uint amountB) {
        address pair = UniswapV2Library.pairFor(factory, tokenA, tokenB);
        IUniswapV2Pair(pair).transferFrom(msg.sender, pair, liquidity); // send liquidity to pair
        (uint amount0, uint amount1) = IUniswapV2Pair(pair).burn(to);
        (address token0,) = UniswapV2Library.sortTokens(tokenA, tokenB);
        (amountA, amountB) = tokenA == token0 ? (amount0, amount1) : (amount1, amount0);
        require(amountA >= amountAMin, 'UniswapV2Router: INSUFFICIENT_A_AMOUNT');
        require(amountB >= amountBMin, 'UniswapV2Router: INSUFFICIENT_B_AMOUNT');
    }
    function removeLiquidityETH(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) public virtual override ensure(deadline) returns (uint amountToken, uint amountETH) {
        (amountToken, amountETH) = removeLiquidity(
            token,
            WETH,
            liquidity,
            amountTokenMin,
            amountETHMin,
            address(this),
            deadline
        );
        TransferHelper.safeTransfer(token, to, amountToken);
        IWETH(WETH).withdraw(amountETH);
        TransferHelper.safeTransferETH(to, amountETH);
    }
    function removeLiquidityWithPermit(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external virtual override returns (uint amountA, uint amountB) {
        address pair = UniswapV2Library.pairFor(factory, tokenA, tokenB);
        uint value = approveMax ? uint(-1) : liquidity;
        IUniswapV2Pair(pair).permit(msg.sender, address(this), value, deadline, v, r, s);
        (amountA, amountB) = removeLiquidity(tokenA, tokenB, liquidity, amountAMin, amountBMin, to, deadline);
    }
    function removeLiquidityETHWithPermit(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external virtual override returns (uint amountToken, uint amountETH) {
        address pair = UniswapV2Library.pairFor(factory, token, WETH);
        uint value = approveMax ? uint(-1) : liquidity;
        IUniswapV2Pair(pair).permit(msg.sender, address(this), value, deadline, v, r, s);
        (amountToken, amountETH) = removeLiquidityETH(token, liquidity, amountTokenMin, amountETHMin, to, deadline);
    }

    // **** REMOVE LIQUIDITY (supporting fee-on-transfer tokens) ****
    function removeLiquidityETHSupportingFeeOnTransferTokens(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) public virtual override ensure(deadline) returns (uint amountETH) {
        (, amountETH) = removeLiquidity(
            token,
            WETH,
            liquidity,
            amountTokenMin,
            amountETHMin,
            address(this),
            deadline
        );
        TransferHelper.safeTransfer(token, to, IERC20(token).balanceOf(address(this)));
        IWETH(WETH).withdraw(amountETH);
        TransferHelper.safeTransferETH(to, amountETH);
    }
    function removeLiquidityETHWithPermitSupportingFeeOnTransferTokens(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external virtual override returns (uint amountETH) {
        address pair = UniswapV2Library.pairFor(factory, token, WETH);
        uint value = approveMax ? uint(-1) : liquidity;
        IUniswapV2Pair(pair).permit(msg.sender, address(this), value, deadline, v, r, s);
        amountETH = removeLiquidityETHSupportingFeeOnTransferTokens(
            token, liquidity, amountTokenMin, amountETHMin, to, deadline
        );
    }

    // **** SWAP ****
    // requires the initial amount to have already been sent to the first pair
    function _swap(uint[] memory amounts, address[] memory path, address _to) internal virtual {
        for (uint i; i < path.length - 1; i++) {
            (address input, address output) = (path[i], path[i + 1]);
            (address token0,) = UniswapV2Library.sortTokens(input, output);
            uint amountOut = amounts[i + 1];
            (uint amount0Out, uint amount1Out) = input == token0 ? (uint(0), amountOut) : (amountOut, uint(0));
            address to = i < path.length - 2 ? UniswapV2Library.pairFor(factory, output, path[i + 2]) : _to;
            IUniswapV2Pair(UniswapV2Library.pairFor(factory, input, output)).swap(
                amount0Out, amount1Out, to, new bytes(0)
            );
        }
    }
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external virtual override ensure(deadline) returns (uint[] memory amounts) {
        amounts = UniswapV2Library.getAmountsOut(factory, amountIn, path);
        require(amounts[amounts.length - 1] >= amountOutMin, 'UniswapV2Router: INSUFFICIENT_OUTPUT_AMOUNT');
        TransferHelper.safeTransferFrom(
            path[0], msg.sender, UniswapV2Library.pairFor(factory, path[0], path[1]), amounts[0]
        );
        _swap(amounts, path, to);
    }
    function swapTokensForExactTokens(
        uint amountOut,
        uint amountInMax,
        address[] calldata path,
        address to,
        uint deadline
    ) external virtual override ensure(deadline) returns (uint[] memory amounts) {
        amounts = UniswapV2Library.getAmountsIn(factory, amountOut, path);
        require(amounts[0] <= amountInMax, 'UniswapV2Router: EXCESSIVE_INPUT_AMOUNT');
        TransferHelper.safeTransferFrom(
            path[0], msg.sender, UniswapV2Library.pairFor(factory, path[0], path[1]), amounts[0]
        );
        _swap(amounts, path, to);
    }
    function swapExactETHForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline)
        external
        virtual
        override
        payable
        ensure(deadline)
        returns (uint[] memory amounts)
    {
        require(path[0] == WETH, 'UniswapV2Router: INVALID_PATH');
        amounts = UniswapV2Library.getAmountsOut(factory, msg.value, path);
        require(amounts[amounts.length - 1] >= amountOutMin, 'UniswapV2Router: INSUFFICIENT_OUTPUT_AMOUNT');
        IWETH(WETH).deposit{value: amounts[0]}();
        assert(IWETH(WETH).transfer(UniswapV2Library.pairFor(factory, path[0], path[1]), amounts[0]));
        _swap(amounts, path, to);
    }
    function swapTokensForExactETH(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline)
        external
        virtual
        override
        ensure(deadline)
        returns (uint[] memory amounts)
    {
        require(path[path.length - 1] == WETH, 'UniswapV2Router: INVALID_PATH');
        amounts = UniswapV2Library.getAmountsIn(factory, amountOut, path);
        require(amounts[0] <= amountInMax, 'UniswapV2Router: EXCESSIVE_INPUT_AMOUNT');
        TransferHelper.safeTransferFrom(
            path[0], msg.sender, UniswapV2Library.pairFor(factory, path[0], path[1]), amounts[0]
        );
        _swap(amounts, path, address(this));
        IWETH(WETH).withdraw(amounts[amounts.length - 1]);
        TransferHelper.safeTransferETH(to, amounts[amounts.length - 1]);
    }
    function swapExactTokensForETH(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline)
        external
        virtual
        override
        ensure(deadline)
        returns (uint[] memory amounts)
    {
        require(path[path.length - 1] == WETH, 'UniswapV2Router: INVALID_PATH');
        amounts = UniswapV2Library.getAmountsOut(factory, amountIn, path);
        require(amounts[amounts.length - 1] >= amountOutMin, 'UniswapV2Router: INSUFFICIENT_OUTPUT_AMOUNT');
        TransferHelper.safeTransferFrom(
            path[0], msg.sender, UniswapV2Library.pairFor(factory, path[0], path[1]), amounts[0]
        );
        _swap(amounts, path, address(this));
        IWETH(WETH).withdraw(amounts[amounts.length - 1]);
        TransferHelper.safeTransferETH(to, amounts[amounts.length - 1]);
    }
    function swapETHForExactTokens(uint amountOut, address[] calldata path, address to, uint deadline)
        external
        virtual
        override
        payable
        ensure(deadline)
        returns (uint[] memory amounts)
    {
        require(path[0] == WETH, 'UniswapV2Router: INVALID_PATH');
        amounts = UniswapV2Library.getAmountsIn(factory, amountOut, path);
        require(amounts[0] <= msg.value, 'UniswapV2Router: EXCESSIVE_INPUT_AMOUNT');
        IWETH(WETH).deposit{value: amounts[0]}();
        assert(IWETH(WETH).transfer(UniswapV2Library.pairFor(factory, path[0], path[1]), amounts[0]));
        _swap(amounts, path, to);
        // refund dust eth, if any
        if (msg.value > amounts[0]) TransferHelper.safeTransferETH(msg.sender, msg.value - amounts[0]);
    }

    // **** SWAP (supporting fee-on-transfer tokens) ****
    // requires the initial amount to have already been sent to the first pair
    function _swapSupportingFeeOnTransferTokens(address[] memory path, address _to) internal virtual {
        for (uint i; i < path.length - 1; i++) {
            (address input, address output) = (path[i], path[i + 1]);
            (address token0,) = UniswapV2Library.sortTokens(input, output);
            IUniswapV2Pair pair = IUniswapV2Pair(UniswapV2Library.pairFor(factory, input, output));
            uint amountInput;
            uint amountOutput;
            { // scope to avoid stack too deep errors
            (uint reserve0, uint reserve1,) = pair.getReserves();
            (uint reserveInput, uint reserveOutput) = input == token0 ? (reserve0, reserve1) : (reserve1, reserve0);
            amountInput = IERC20(input).balanceOf(address(pair)).sub(reserveInput);
            amountOutput = UniswapV2Library.getAmountOut(amountInput, reserveInput, reserveOutput);
            }
            (uint amount0Out, uint amount1Out) = input == token0 ? (uint(0), amountOutput) : (amountOutput, uint(0));
            address to = i < path.length - 2 ? UniswapV2Library.pairFor(factory, output, path[i + 2]) : _to;
            pair.swap(amount0Out, amount1Out, to, new bytes(0));
        }
    }
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external virtual override ensure(deadline) {
        TransferHelper.safeTransferFrom(
            path[0], msg.sender, UniswapV2Library.pairFor(factory, path[0], path[1]), amountIn
        );
        uint balanceBefore = IERC20(path[path.length - 1]).balanceOf(to);
        _swapSupportingFeeOnTransferTokens(path, to);
        require(
            IERC20(path[path.length - 1]).balanceOf(to).sub(balanceBefore) >= amountOutMin,
            'UniswapV2Router: INSUFFICIENT_OUTPUT_AMOUNT'
        );
    }
    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    )
        external
        virtual
        override
        payable
        ensure(deadline)
    {
        require(path[0] == WETH, 'UniswapV2Router: INVALID_PATH');
        uint amountIn = msg.value;
        IWETH(WETH).deposit{value: amountIn}();
        assert(IWETH(WETH).transfer(UniswapV2Library.pairFor(factory, path[0], path[1]), amountIn));
        uint balanceBefore = IERC20(path[path.length - 1]).balanceOf(to);
        _swapSupportingFeeOnTransferTokens(path, to);
        require(
            IERC20(path[path.length - 1]).balanceOf(to).sub(balanceBefore) >= amountOutMin,
            'UniswapV2Router: INSUFFICIENT_OUTPUT_AMOUNT'
        );
    }
    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    )
        external
        virtual
        override
        ensure(deadline)
    {
        require(path[path.length - 1] == WETH, 'UniswapV2Router: INVALID_PATH');
        TransferHelper.safeTransferFrom(
            path[0], msg.sender, UniswapV2Library.pairFor(factory, path[0], path[1]), amountIn
        );
        _swapSupportingFeeOnTransferTokens(path, address(this));
        uint amountOut = IERC20(WETH).balanceOf(address(this));
        require(amountOut >= amountOutMin, 'UniswapV2Router: INSUFFICIENT_OUTPUT_AMOUNT');
        IWETH(WETH).withdraw(amountOut);
        TransferHelper.safeTransferETH(to, amountOut);
    }

    // **** LIBRARY FUNCTIONS ****
    function quote(uint amountA, uint reserveA, uint reserveB) public pure virtual override returns (uint amountB) {
        return UniswapV2Library.quote(amountA, reserveA, reserveB);
    }

    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut)
        public
        pure
        virtual
        override
        returns (uint amountOut)
    {
        return UniswapV2Library.getAmountOut(amountIn, reserveIn, reserveOut);
    }

    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut)
        public
        pure
        virtual
        override
        returns (uint amountIn)
    {
        return UniswapV2Library.getAmountIn(amountOut, reserveIn, reserveOut);
    }

    function getAmountsOut(uint amountIn, address[] memory path)
        public
        view
        virtual
        override
        returns (uint[] memory amounts)
    {
        return UniswapV2Library.getAmountsOut(factory, amountIn, path);
    }

    function getAmountsIn(uint amountOut, address[] memory path)
        public
        view
        virtual
        override
        returns (uint[] memory amounts)
    {
        return UniswapV2Library.getAmountsIn(factory, amountOut, path);
    }
}
