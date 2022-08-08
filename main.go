package main

import (
    "crypto/sha256"
    "fmt"
    "os"
    "time"

    "./sha2"
)

func main() {
    msg, err := os.ReadFile("loremipsum.txt")
    if err != nil {
        panic(err)
    }

    message := []byte(msg)

    myStart := time.Now()
    myHash := sha2.Hash256(message)
    myEnd := time.Now()

    myElapsed := myEnd.Sub(myStart)
    fmt.Println("my sha256: ", myElapsed, "\n", myHash)

    stdStart := time.Now()
    stdHash := sha256.Sum256(message)
    stdEnd := time.Now()

    stdElapsed := stdEnd.Sub(stdStart)
    fmt.Println("std sha256: ", stdElapsed, "\n", stdHash)
}
