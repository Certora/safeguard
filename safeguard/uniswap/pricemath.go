package main

import (
	"math/big"

	"github.com/holiman/uint256"
)

type NamedConstants struct {
	uint256Max, oneShiftLeft32, uint160Max, Q96, Q128 *uint256.Int
}

type PriceComputation struct {
	a *big.Int
	b *big.Int

	zero  *uint256.Int
	ratio *uint256.Int

	sqrtRatioAX96 *uint256.Int
	sqrtRatioBX96 *uint256.Int

	numerator1 *uint256.Int
	numerator2 *uint256.Int

	leftPrice  *uint256.Int
	rightPrice *uint256.Int
	/*
	  magic constants that appear in the sqrt math
	  0: 0xfffcb933bd6fad37aa2d162d1a594001
	  1: 0x100000000000000000000000000000000
	  the two constants used as the initial values of ratio
	  2 -- 21
	  the magic constants by which ratio is multiplied, in the order the multiplication occurs
	  e.g.,
	  2: 0xfff97272373d413259a46990580e213a
	  3: 0xfff2e50f5f656932ef12357cf3c7fdcc
	  etc.
	*/
	sqrtRatioConsts [21]*uint256.Int

	/*
	   Magic "masks" involved in other computations.
	   0: uint256 max
	   1: 1 << 32
	   2: uint160 max
	   2: Q96 aka (0x1000000000000000000000000)
	*/
	namedConstant NamedConstants
}

func (pc *PriceComputation) getSqrtRatioAtTick(tick int) {
	var absTick uint64
	if tick < 0 {
		absTick = uint64(-tick)
	} else {
		absTick = uint64(tick)
	}
	pc.ratio.SetUint64(absTick)
	lowerBytes := pc.ratio[0]
	if lowerBytes&1 != 0 {
		pc.ratio.Set(pc.sqrtRatioConsts[0])
	} else {
		pc.ratio.Set(pc.sqrtRatioConsts[1])
	}
	for i := 0; i < 19; i++ {
		bitTest := 1 << (i + 1)
		if lowerBytes&uint64(bitTest) != 0 {
			pc.ratio.Mul(pc.ratio, pc.sqrtRatioConsts[i+2])
			pc.ratio.Rsh(pc.ratio, 128)
		}
	}
	// aka tick is positive
	if tick > 0 {
		pc.ratio.Div(pc.namedConstant.uint256Max, pc.ratio)
	}
	pc.zero.Mod(pc.ratio, pc.namedConstant.oneShiftLeft32)
	var adjust uint64 = 1
	if pc.zero.IsZero() {
		adjust = 0
	}
	pc.zero.Clear()
	pc.ratio.Rsh(pc.ratio, 32)
	pc.ratio.AddUint64(pc.ratio, adjust)
	pc.ratio.And(pc.ratio, pc.namedConstant.uint160Max)
}

func toBigFast(bigint *big.Int, z *uint256.Int) {
	words := [4]big.Word{big.Word(z[0]), big.Word(z[1]), big.Word(z[2]), big.Word(z[3])}
	bigint.SetBits(words[:])
}

func (pc *PriceComputation) getAmount0DeltaRoundDown(
	liquidity *uint256.Int,
	out *uint256.Int,
) {
	pc.numerator1.Lsh(liquidity, 96)
	pc.numerator2.Sub(pc.sqrtRatioBX96, pc.sqrtRatioAX96)
	toBigFast(pc.a, pc.numerator1)
	toBigFast(pc.b, pc.numerator2)
	pc.a.Mul(pc.a, pc.b)
	toBigFast(pc.b, pc.sqrtRatioBX96)
	pc.a.Div(pc.a, pc.b)
	out.SetFromBig(pc.a)
	out.Div(out, pc.sqrtRatioAX96)
}

func (pc *PriceComputation) mulDiv(
	mul1, mul2, div, out *uint256.Int,
) {
	toBigFast(pc.a, mul1)
	toBigFast(pc.b, mul2)
	pc.a.Mul(pc.a, pc.b)
	toBigFast(pc.b, div)
	pc.a.Div(pc.a, pc.b)
	out.SetFromBig(pc.a)
}

func (pc *PriceComputation) getAmount1DeltaRoundDown(
	liquidity *uint256.Int,
	out *uint256.Int,
) {
	pc.numerator1.Set(liquidity)
	pc.numerator2.Sub(pc.sqrtRatioBX96, pc.sqrtRatioAX96)
	pc.mulDiv(pc.numerator1, pc.numerator2, pc.namedConstant.Q96, out)
}

var pcCache *PriceComputation

func initPC() {
	zero := new(uint256.Int)
	max := new(uint256.Int)
	max.SubUint64(zero, 1)
	modConst := uint256.NewInt(1)
	modConst.Lsh(modConst, 32)
	pcCache = &PriceComputation{
		a:             big.NewInt(0),
		b:             big.NewInt(1),
		zero:          zero,
		ratio:         new(uint256.Int),
		sqrtRatioAX96: new(uint256.Int),
		sqrtRatioBX96: new(uint256.Int),
		numerator1:    new(uint256.Int),
		numerator2:    new(uint256.Int),
		leftPrice:     new(uint256.Int),
		rightPrice:    new(uint256.Int),
		sqrtRatioConsts: [21]*uint256.Int{
			uint256.MustFromHex("0xfffcb933bd6fad37aa2d162d1a594001"),
			uint256.MustFromHex("0x100000000000000000000000000000000"),
			uint256.MustFromHex("0xfff97272373d413259a46990580e213a"),
			uint256.MustFromHex("0xfff2e50f5f656932ef12357cf3c7fdcc"),
			uint256.MustFromHex("0xffe5caca7e10e4e61c3624eaa0941cd0"),
			uint256.MustFromHex("0xffcb9843d60f6159c9db58835c926644"),
			uint256.MustFromHex("0xff973b41fa98c081472e6896dfb254c0"),
			uint256.MustFromHex("0xff2ea16466c96a3843ec78b326b52861"),
			uint256.MustFromHex("0xfe5dee046a99a2a811c461f1969c3053"),
			uint256.MustFromHex("0xfcbe86c7900a88aedcffc83b479aa3a4"),
			uint256.MustFromHex("0xf987a7253ac413176f2b074cf7815e54"),
			uint256.MustFromHex("0xf3392b0822b70005940c7a398e4b70f3"),
			uint256.MustFromHex("0xe7159475a2c29b7443b29c7fa6e889d9"),
			uint256.MustFromHex("0xd097f3bdfd2022b8845ad8f792aa5825"),
			uint256.MustFromHex("0xa9f746462d870fdf8a65dc1f90e061e5"),
			uint256.MustFromHex("0x70d869a156d2a1b890bb3df62baf32f7"),
			uint256.MustFromHex("0x31be135f97d08fd981231505542fcfa6"),
			uint256.MustFromHex("0x9aa508b5b7a84e1c677de54f3e99bc9"),
			uint256.MustFromHex("0x5d6af8dedb81196699c329225ee604"),
			uint256.MustFromHex("0x2216e584f5fa1ea926041bedfe98"),
			uint256.MustFromHex("0x48a170391f7dc42444e8fa2"),
		},
		namedConstant: NamedConstants{
			uint256Max:     max,
			oneShiftLeft32: modConst,
			uint160Max:     uint256.MustFromHex("0xffffffffffffffffffffffffffffffffffffffff"),
			Q96:            uint256.MustFromHex("0x1000000000000000000000000"),
			Q128:           uint256.MustFromHex("0x100000000000000000000000000000000"),
		},
	}
}

func getPC() *PriceComputation {
	return pcCache
}
