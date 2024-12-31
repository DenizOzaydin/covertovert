# Protocol Field Manipulation DNS Answer Type

## Encoding

The process of encoding and decoding the message is in this way:

When the sender will send 4 bits, these bits are converted into a decimal number:

For example, the bits will be sent are 0110, it is converted into 6.

The package with answer 1 is sent 6 times, and the package with answer 5 will be sent 1 times.

Finally, the packages that contains an answer will be sent are "1111115".

## Decoding

When a package with answer 5 is received, the previous consequent 1's are summed up.

If a sequence like "1111115" is received, there are 6 consequent 1's ending with 5.

The number is turned into a binary string, with length 4 and added to the decoded string.

## Limits

Covert Channel Capacity: 7.53 bps