package dashboard

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

type KeySelector interface {
	KeyName() string
}

type PlainId string

func (p PlainId) KeyName() string {
	return "id"
}

func GetConditionResult(name string, status bool, values ...any) map[string]interface{} {
	vDict := make(map[string]interface{})
	var currKey string
	for i, r := range values {
		if i%2 == 0 {
			k, ok := r.(string)
			if !ok {
				currKey = fmt.Sprintf("BADKEY!%d", i)
			} else {
				currKey = k
			}
		} else {
			switch v := r.(type) {
			case int:
				vDict[currKey] = v
			case string:
				vDict[currKey] = v
			case bool:
				vDict[currKey] = v
			case uint64:
				vDict[currKey] = v
			case *uint256.Int:
				vDict[currKey] = v.Hex()
			default:
				vDict[currKey] = fmt.Sprintf("BADVALUE!%d", i)
			}
		}
	}
	if len(values)%2 == 1 {
		vDict[currKey] = "!MISSING"
	}
	return map[string]interface{}{
		"condition": name,
		"status":    status,
		"values":    vDict,
	}
}

type PlainString string

func (p PlainString) String() string {
	return string(p)
}

type LowerString string

func (l LowerString) String() string {
	return strings.ToLower(string(l))
}

type NormalizedAddress common.Address

func (n NormalizedAddress) String() string {
	return strings.ToLower(common.Address(n).Hex())
}

func GetDashboardMessageGen[T KeySelector, ID fmt.Stringer](blockNumber big.Int, id ID, holds bool, cond map[string]interface{}, others ...map[string]interface{}) map[string]interface{} {
	var impl T
	var statusString string
	if holds {
		statusString = "success"
	} else {
		statusString = "failure"
	}
	std := map[string]interface{}{
		"invariantStatus":      statusString,
		"blockNumber":          blockNumber.Uint64(),
		"calculationTimestamp": time.Now().Unix(),
		"conditionsChecked":    append([]map[string]interface{}{cond}, others...),
	}
	std[impl.KeyName()] = id.String()
	return std
}

func GetDashboardMessage(blockNumber big.Int, id string, holds bool, cond map[string]interface{}, others ...map[string]interface{}) map[string]interface{} {
	return GetDashboardMessageGen[PlainId](blockNumber, PlainString(id), holds, cond)
}

func GetDashboardErrorMessageGen[T KeySelector, ID fmt.Stringer](blockNumber big.Int, id ID, err error) map[string]interface{} {
	std := map[string]interface{}{
		"invariantStatus":      "error",
		"blockblockNumber":     blockNumber.Uint64(),
		"calculationTimestamp": time.Now().Unix(),
		"error":                err.Error(),
	}
	var impl T
	std[impl.KeyName()] = id.String()
	return std
}

func GetDashboardErrorMessage(blockNumber big.Int, id string, err error) map[string]interface{} {
	return GetDashboardErrorMessageGen[PlainId, PlainString](blockNumber, PlainString(id), err)
}
