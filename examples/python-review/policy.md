# Order-processing requirements

Shipping costs 500 cents for an order below 5,000 cents and zero for an order of at least
5,000 cents. The same threshold applies to express shipping in this example.

The member and renewal discounts are 20 percent only when `member` is the boolean `True`.
All other values, including strings, receive a 5 percent discount.

Order and return decoders must propagate invalid-JSON errors to their caller. An empty
dictionary is a valid decoded value and must not substitute for a decoding error.

Contact and billing email normalization must remove leading and trailing whitespace and
convert letters to lowercase. The input is a string.

Note and message functions may append to a caller-supplied list. Calls that omit the list
must each return a distinct list object containing no items carried over from earlier calls.
