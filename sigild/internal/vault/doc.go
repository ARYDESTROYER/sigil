// Package vault will hold the encrypted-blob operation log: accepting signed,
// encrypted CRDT operations, storing them in object storage keyed by vault and
// operation ID, and serving them back by Lamport-clock cursor. sigild never
// decrypts or interprets operation contents — only validates signatures and sizes.
//
// STATUS: pre-audit skeleton — not implemented.
package vault
