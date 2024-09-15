package tc

import (
	"fmt"
	"reflect"
)

type TCHandler struct {
}

func (tc *TCHandler) readInterfaces() error {
	return nil 
}

func NodeTcHandler(id ...interface{}) interface{} {
	for _, val := range id {
		switch reflect.TypeOf(val).Kind() {
		case reflect.Array:
			{
				fmt.Println(reflect.TypeOf(val))

			}
		}
	}
	return nil
}

