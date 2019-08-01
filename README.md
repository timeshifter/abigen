# ABI Datagen UI/API

Link to web UI is [here](https://timeshifter.github.io/abigen/datagen.html)

## Web UI

The web UI is divided into two sections: the validator, and the generator.

#### Validator

This section allows you to paste in contract text and a formatted data string, and it will display either any per-parameter errors discovered, or the encoded value of that parameter. It will also display the encoded data block for the entire ABI/data string pair.

#### Generator

Here you can construct an ABI and data string. Whenever a parameter name is entered, a new row will automatically appear. Input values are validated in real time, and if no errors are found, the resulting ABI, data string, and encoded data will all be displayed.

## API

The JS API is designed to be entirely self-contained and as simple to use as possible; it is one file, which can be found [here](https://timeshifter.github.io/abigen/datagen.js). It provides an object named `ABIdatagen` that contains all of the methods required to validate and encode data. All errors are thrown as exceptions. If no exceptions are thrown, validation succeeded and the encoded value is returned.

#### Primitives

```javascript
ABIdatagen.EncodeValue(type, value);
```

This method encodes any number/char/array types.

`type` should be provided as a `string`.

`value` can be either a `string` or a `Number`; base10 and base16 are both supported.

#### UniversalAddress

```javascript
ABIdatagen.EncodeUA(uniaddress);
```

This method validates the integrity of a uniaddress, including invalid base58 characters, length, and checksum. 

#### Function

```javascript
ABIdatagen.GetFunctionID(abi);
```

This function accepts an ABI string as its input, and returns its function ID.

### Encode complete ABI/data string

```javascript
ABIdatagen.GetData(abiStr, dataStr);
```

This will validate and encode a complete ABI and data string pair, returning the entire encoded data.