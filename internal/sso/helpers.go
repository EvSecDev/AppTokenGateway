package sso

import (
	"fmt"
	"net/http"
)

func UserFrom(request *http.Request) (claims UserClaims, err error) {
	value := request.Context().Value(ctxKey{})
	claims, ok := value.(UserClaims)
	if !ok {
		err = fmt.Errorf("expected type UserClaims but got %T", value)
	}
	return
}
