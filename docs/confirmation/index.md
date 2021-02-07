---
layout: default
title: Confirmation
nav_order: 9
has_children: true
---

Confirmation
===

The `Auth` class takes as confirmation service that can be use to create and verify confirmation tokens. This is useful
to require a user to confirm signup by e-mail or for a password reset functionality.

## No confirmation

By default, the `Auth` service has a stub object that can't create confirmation tokens. Using `$auth->confirm()`, without
passing a confirmation when creating `Auth`, will throw an exception.

## Random token

The `TokenConfirmation` service generates a random token. The token needs to be stored in the database in
such a way that the user information can be fetched for a URL that has the token as query parameter.

[more &raquo;](token.md)

## Hashids

The `HashidsConfirmation` service creates tokens that includes the user id, expire date, and a checksum
using the [Hashids](https://hashids.org/php/) library.

[more &raquo;](token.md)

## Custom confirmation service

It's possible to create a custom confirmation service by implementing the `ConfirmationInterface`. The service should
be immutable.
