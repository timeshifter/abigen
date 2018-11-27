var ABIGen = {

    TypeMap: {
        'uint8': 'uint8_t',
        'uint16': 'uint16_t',
        'uint32': 'uint32_t',
        'uint64': 'uint64_t',
        'int8': 'int8_t',
        'int16': 'int16_t',
        'int32': 'int32_t',
        'int64': 'int64_t',
        'char': 'char',
        'void': 'void',
        'UniversalAddress': 'UniversalAddressABI*'
    },

    ParseContract: function (contractText) {
        var lines = contractText.split('\n');
        var output = {};

        for (l of lines) {
            if (l.trim().indexOf(':name=') === 0) {
                output.ContractName = l.split('#')[0].split('=')[1].trim();

            }
            else if (l.indexOf('->') > -1 && l.trim()[0] !== '#') {

                var sides = l.split('#')[0].split('->').map(function (t) { return t.trim(); });

                var in_parts = sides[0].split(' ').map(function (t) { return t.trim(); }),
                    out_parts = sides[1].split(' ').map(function (t) { return t.trim(); });

                output.InputParams = {};
                var p_parts;

                for (p of in_parts) {
                    p_parts = p.split(':');
                    if (p_parts.length === 1 && p_parts[0] !== 'void') {
                        throw 'Unrecognized syntax on left side of function definition (' + p + ').';
                    }

                    if (p_parts[1] === 'fn') {
                        output.FunctionName = p_parts[0];
                    }
                    else {
                        if (!this.TypeMap[p_parts[1]]) {
                            throw 'Unknown input type (' + p + ').';
                        }

                        output.InputParams[p_parts[0]] = this.TypeMap[p_parts[1]];

                    }

                }

                output.OutputParams = {};

                for (p of out_parts) {
                    p_parts = p.split(':');
                    if (p_parts.length === 1 && p_parts[0] !== 'void') {
                        throw 'Unrecognized syntax on left side of function definition (' + p + ').';
                    }

                    if (p_parts[1] === 'fn') {
                        output.FunctionName = p_parts[0];
                    }
                    else if (p === 'void') {
                        output.OutputParams['void'] = 'void';
                    }
                    else {
                        if (!this.TypeMap[p_parts[1]]) {
                            throw 'Unknown output type (' + p + ').';
                        }

                        output.OutputParams[p_parts[0]] = this.TypeMap[p_parts[1]];

                    }

                }

            }
        }
        if (!output.ContractName) {
            throw 'Contract does not have a name.';
        }
        if (!output.FunctionName) {
            throw 'Contract has no function name.';
        }

        return output;
    },

    EncodeSeed: 1,

    GenerateEncode_BasicTypes: function (contractText) {
        var _template =
            `
#ifndef ABI_HEADER_{contract_name}
#define ABI_HEADER_{contract_name}
typedef struct {
{struct_input_vars}
} {contract_name}_{func_name}_params;

{return_struct}

#define __ABIFN_{contract_name}_{func_name} ${this.EncodeSeed}

static QtumCallResultABI {contract_name}_{func_name}(const UniversalAddressABI* contract,
    uint64_t gasLimit,
    const {contract_name}_{func_name}_params* params{return_params}
    )
{
    if (gasLimit == 0) {
        gasLimit = QTUM_CALL_GASLIMIT;
    }
    qtumStackClear();
    if (params == NULL) {
        qtumError("Invalid parameters");
    }
{stack_push}
    uint32_t f = __ABIFN_{contract_name}_{func_name};
    qtumStackPush(&f, sizeof(f));
    QtumCallResultABI result;
    qtumCallContract(contract, gasLimit, 0, &result);
    if (result.errorCode != 0) {
        return result;
    }
{stack_clear}
    return result;
}
#endif
`;
        this.EncodeSeed++;
        var contractMeta = this.ParseContract(contractText);


        var varPass = false;
        for (i in contractMeta.InputParams)
            if (contractMeta.InputParams[i] === 'UniversalAddressABI*')
                varPass = true;
        for (i in contractMeta.OutputParams)
            if (contractMeta.OutputParams[i] === 'UniversalAddressABI*')
                varPass = true;

        if (varPass)
            throw "BasicTypes encoder selected, but UniversalAddress parameter provided.";



        var output = _template
            .replace(/{contract_name}/g, contractMeta.ContractName)
            .replace(/{func_name}/g, contractMeta.FunctionName);

        var struct_input = '', stack_push = '';
        for (i in contractMeta.InputParams) {
            struct_input += `    ${contractMeta.InputParams[i]} ${i};\n`;
            stack_push += `    qtumStackPush(&params->${i}, sizeof(params->${i}));\n`;
        }

        output = output
            .replace('{struct_input_vars}', struct_input.substring(0, struct_input.length - 1))
            .replace('{stack_push}', stack_push.substring(0, stack_push.length - 1));


        if (contractMeta.OutputParams['void']) {
            output = output
                .replace('{return_struct}', '')
                .replace('{return_params}', '')
                .replace('{stack_clear}', '');
        }
        else {


            var struct_return = `
typedef struct {\n`,
                stack_pop = `
    if (returns == NULL) {
        qtumStackClear();
    } 
    else {
    \n`;
            for (i in contractMeta.OutputParams) {
                struct_return += `    ${contractMeta.OutputParams[i]} ${i};\n`;
                stack_pop += `        qtumStackPop(&returns->${i}, sizeof(returns->${i}));\n`;
            }
            struct_return += `} ${contractMeta.ContractName}_${contractMeta.FunctionName}_returns;\n`;
            stack_pop += '    }\n';
            output = output
                .replace('{return_struct}', struct_return.substring(0, struct_return.length - 1))
                .replace('{stack_clear}', stack_pop)
                .replace('{return_params}', `,
    ${contractMeta.ContractName}_${contractMeta.FunctionName}_returns* returns`);
        }


        return output;


    },



    GenerateEncode_UniversalAddress: function (contractText) {
        var _template =
            `
typedef struct {
{struct_input_vars}
} {contract_name}_{func_name}_params;

{return_struct}

#define __ABIFN_{contract_name}_{func_name} ${this.EncodeSeed}

static QtumCallResultABI {contract_name}_{func_name}(const UniversalAddressABI* contract,
    uint64_t gasLimit,
    const {contract_name}_{func_name}_params* params{return_params}
    )
{
    if (gasLimit == 0) {
        gasLimit = QTUM_CALL_GASLIMIT;
    }
    qtumStackClear();
    if (params == NULL) {
        qtumError("Invalid parameters");
    }
{stack_push}
    uint32_t f = __ABIFN_{contract_name}_{func_name};
    qtumStackPush(&f, sizeof(f));
    QtumCallResultABI result;
    qtumCallContract(contract, gasLimit, 0, &result);
    if (result.errorCode != 0) {
        return result;
    }
{stack_clear}
    return result;
}
`;
        this.EncodeSeed++;
        var contractMeta = this.ParseContract(contractText);

        var varPass = false;
        for (i in contractMeta.InputParams)
            if (contractMeta.InputParams[i] === 'UniversalAddressABI*')
                varPass = true;
        for (i in contractMeta.OutputParams)
            if (contractMeta.OutputParams[i] === 'UniversalAddressABI*')
                varPass = true;

        if (!varPass)
            throw "UniversalAddress encoder selected, but no UniversalAddress parameter provided.";


        var output = _template
            .replace(/{contract_name}/g, contractMeta.ContractName)
            .replace(/{func_name}/g, contractMeta.FunctionName);

        var struct_input = '', stack_push = '';
        for (i in contractMeta.InputParams) {
            struct_input += `    ${contractMeta.InputParams[i]} ${i};\n`;
            if (contractMeta.InputParams[i] === 'UniversalAddressABI*') {
                stack_push += `
    if(params->${i} == NULL){
        qtumError("Invalid parameters");
    }
    qtumStackPush(params->${i}, sizeof(*params->${i}));\n`;
            }
            else {
                stack_push += `    qtumStackPush(&params->${i}, sizeof(params->${i}));\n`;
            }
       }

        output = output
            .replace('{struct_input_vars}', struct_input.substring(0, struct_input.length - 1))
            .replace('{stack_push}', stack_push.substring(0, stack_push.length - 1));




        if (contractMeta.OutputParams['void']) {
            output = output
                .replace('{return_struct}', '')
                .replace('{return_params}', '')
                .replace('{stack_clear}', '');
        }
        else {


            var struct_return = `
typedef struct {\n`,
                stack_pop = `
    if (returns == NULL) {
        qtumStackClear();
    } 
    else {
    \n`;
            for (i in contractMeta.OutputParams) {
                struct_return += `    ${contractMeta.OutputParams[i]} ${i};\n`;
                if (contractMeta.OutputParams[i] === 'UniversalAddressABI*') {
                    stack_pop += `
        if(returns->${i} == NULL){
            qtumStackDiscard();
        }else{
            qtumStackPop(returns->${i}, sizeof(*returns->${i}));
        }
`;
                }
                else {


                    stack_pop += `        qtumStackPop(&returns->${i}, sizeof(returns->${i}));\n`;
                }
            }
            struct_return += `} ${contractMeta.ContractName}_${contractMeta.FunctionName}_returns;\n`;
            stack_pop += '    }\n';
            output = output
                .replace('{return_struct}', struct_return.substring(0, struct_return.length - 1))
                .replace('{stack_clear}', stack_pop)
                .replace('{return_params}', `,
    ${contractMeta.ContractName}_${contractMeta.FunctionName}_returns* returns`);
        }



        return output;
    },

    GenerateDecodeFunction: function (contractText) {


        var _template = `
void qtumabi_{contract_name}_decodeABI(){
    uint32_t function = 0;
    if(qtumStackItemCount() == 0){
        qtumabi_default();
    }
    qtumStackPop(&function, sizeof(function));
    switch(function){
{case}
        //{case_insert}
        default:
            qtumabi_fallback();
            return;
    }
}`;

        var contractMeta = this.ParseContract(contractText);
        var output = _template
            .replace(/{contract_name}/g, contractMeta.ContractName)
            .replace(/{case}/g, this.GenerateDecodeCase(contractText));

        return output;

    },

    GenerateDecodeCase: function (contractText) {

        var _template = `
        case __ABIFN_{contract_name}_{func_name}:
        {
            {contract_name}_{func_name}_Params params;
{params}

            {contract_name}_{func_name}_Returns returns;
{returns_buffer}

            {contract_name}_{func_name}(&params, &returns);
{returns_push}
            return;
        }`;

        var contractMeta = this.ParseContract(contractText);
        var output = _template
            .replace(/{contract_name}/g, contractMeta.ContractName)
            .replace(/{func_name}/g, contractMeta.FunctionName);

        var i = 1;
        var params_buffer = '', params_pop = '';

        for (param in contractMeta.InputParams) {
            if (contractMeta.InputParams[param] === 'UniversalAddressABI*') {
                params_buffer += `
            UniversalAddressABI __tmp${i};
            params.${param} = &__tmp${i++};`;

                params_pop += `
            qtumStackPop(params.${param}, sizeof(*params.${param}));`;
            }
            else {
                params_pop += `
            qtumStackPop(&params.${param}, sizeof(params.${param}));`;
            }
        }

        output = output.replace(/{params}/g, params_buffer + `\n` + params_pop);

        var return_buffer = '', return_push = '';

        for (param in contractMeta.OutputParams) {
            if (contractMeta.OutputParams[param] === 'UniversalAddressABI*') {
                return_buffer += `
            UniversalAddressABI __tmp${i};
            returns.${param} = &__tmp${i++};`;

                return_push += `
            qtumStackPush(returns.${param}, sizeof(*returns.${param}));`;
            }
            else {
                return_push += `
            qtumStackPush(&returns.${param}, sizeof(returns.${param}));`;
            }
        }

        output = output
            .replace(/{returns_buffer}/, return_buffer)
            .replace(/{returns_push}/, return_push);


        return output;

    }


};
