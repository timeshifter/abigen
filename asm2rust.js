ASM2Rust = {

    ArgList: {
        'moffs8':                           'with_offs8()',
        'moffs16':                          'with_offs16()',
        'moffs32':                          'with_offs32()',
        'moffs16+moffs32':                  'with_offsw()',
        'AL|CL|DL|BL|AH|CH|DH|BH':          'with_arg(HardcodedRegister(Reg8::{0} as u8), Fixed(Byte))',
        'AX|CX|DX|BX|SP|BP|DI|SI':          'with_arg(HardcodedRegister(Reg16::{0} as u8), Fixed(Word))',
        'EAX|ECX|EDX|EBX|ESP|EBP|EDI|ESI':  'with_arg(HardcodedRegister(Reg32::{0} as u8), Fixed(Dword))',
        'r/m8':                             'with_rm8()',
        'r/m16':                            'with_rm16()',
        'r/m32':                            'with_rm32()',
        'r/m16+r/m32':                      'with_rmw()',
        'imm8':                             'with_imm8()',
        'imm16':                            'with_imm16()',
        'imm32':                            'with_imm32()',
        'imm16+imm32':                      'with_immw()',
        'rel8':                             'with_arg(ArgSource::JumpRel, Fixed(Byte))',
        'rel16|rel32':                      'with_arg(ArgSource::JumpRel, NativeWord)',
        '/r': {
            'r8':                           'with_rm_reg8()',
            'r16':                          'with_rm_reg16()',
            'r32':                          'with_rm_reg32()',
            'r16+r32':                      'with_rm_regw()'
        },
        '+r': {
            'r8':                           'with_suffix_reg8()',
            'r16':                          'with_suffix_reg16()',
            'r32':                          'with_suffix_reg32()',
            'r16+r32':                      'with_suffix_regw()'
        }
    },

    IgnoreOps: ['LODS', 'MOVS', 'SCAS', 'STOS', 'CMPS', 'IMUL'],

    Convert: function (asmStr) {
        var lines = asmStr.split('\n').map(s => { s = s.trim(); while (s.indexOf('  ') > -1) { s = s.replace('  ', ' '); } return s; }), result = '';
        var i = 0;
        while (i < lines.length) {
            if (lines[i] == '')
                lines.splice(i, 1);
            else {
                //check for condensed opcode def and expand
                if (lines[i].indexOf(';') > -1) {
                    var parts = lines[i].split(';').map(s => { return s.trim(); });
                    var argparts = parts[2].split(' ')[4].split('/'),
                        oppart = parts[2].split(' ')[3];
                    parts[2] = parts[2].split(' ').splice(0, 3).join(' ');
                    for (var p in parts) {
                        lines.splice(i, 0, parts[p] + ' ' + oppart + ' ' + argparts[p]);
                        i++;
                    }
                    lines.splice(i, 1);
                    i--;
                    //console.log(parts, argparts, oppart);

                }
                i++;
            }
        }

        i = 0;

        var ops = [];

        while (i < lines.length) {
            var parts = lines[i].split(' ');

            var is_extended = false,
                opcode = '',
                is_modrm_reg = false,
                is_reg_suffix = false,
                group_id = -1,
                op = '',
                args = '',
                orig = lines[i]
                ;

            if (parts[0] == '0F') {
                is_extended = true;
                parts.splice(0, 1);
            }

            opcode = parts[0];
            parts.splice(0, 1);

            if (parts[0] == '/r') {
                is_modrm_reg = true;
                parts.splice(0, 1);
            }
            else if (parts[0] == '+r' || parts[0] == '+') {
                is_reg_suffix = true;
                parts.splice(0, 1);
            }
            
            if (/\/[0-7]/.test(parts[0])) {
                group_id = parts[0][1];
                parts.splice(0, 1);
            }

            if (/[a-z]{2}/.test(parts[0])) {
                parts.splice(0, 1);
            }

            op = parts[0];
            parts.splice(0, 1);

            if (parts.length > 0) {
                args = parts[0];
            }

            ops.push({
                opcode: opcode,
                extended: is_extended,
                modrm_reg: is_modrm_reg,
                reg_suffix: is_reg_suffix,
                group_id: group_id,
                operation: op,
                args: args,
                source: orig
            });
            
            i++;
        }

        var groups_checked = [];

        i = 0;
        while (i < ops.length) {

            var group = ops.filter(e => e.opcode == ops[i].opcode && e.extended == ops[i].extended && e.group_id == ops[i].group_id);
            i++;
            var gstr = `${group[0].extended ? '0F' : ''}${group[0].opcode}_${group[0].group_id}`;

            if (groups_checked.indexOf(gstr) > -1)
                continue;
            else
                groups_checked.push(gstr);


            for (g of group) {
                result += `    //${g.source}\n`;
            }

            //single op
            if (group.length == 1) {
                var t = new this.TestObj();
                t.group = true;
                var r = `    define_opcode(0x${group[0].opcode})`;

                t.extended = true;
                if (group[0].extended) {
                    r += '.is_extended()';
                }
                
                t.group_id = true;
                if (group[0].group_id != -1) {
                    r += `.is_group(${group[0].group_id})`;
                }

                r += `.calls(ops::${group[0].operation.toLowerCase()}).with_gas(GAS_PLACEHOLDER) \n`;


                t.args = true;
                if (group[0].args != '') {
                    var args = group[0].args.split(',');
                    for (a of args) {

                        //m8/m16/m32 WITH /0 through /7 -- Same as rm8/rm16/rm32
                        if (/^m(8|16|32)$/.test(a) && group[0].group_id != -1) {
                            a = 'r' + a;
                        }

                        t.modrm = true;
                        t.reg_suf = true;

                        if (group[0].modrm_reg && this.ArgList['/r'][a]) {
                            requestAnimationFrame += '        .' + this.ArgList['/r'][a] + `\n`;
                        }
                        else if (group[0].reg_suffix && this.ArgList['+r'][a]) {
                            r += '        .' + this.ArgList['+r'][a] + `\n`;
                        }
                        else if (/^\d{1}$/.test(a)) {
                            r += `        .with_arg(Literal(${a}), Fixed(Byte))\n`;
                        }
                        else if (/^m(8|16|32)$/.test(a)) {
                            r = `//TODO - m8/m16/m32 WITHOUT /0 through /7 -- Exceptional, ask earlz\n`;
                            break;
                        }
                        else {
                            var t_a = '';
                            for (arg in this.ArgList) {
                                if (arg.split('|').indexOf(a) != -1) {
                                    t_a = this.ArgList[arg];
                                }
                            }
                            t_a = t_a.replace('{0}', a);

                            if (t_a.trim() == '') {
                                r = `//TODO - um wat?\n`
                            }
                            else {
                                r += '        .' + t_a + `\n`;
                            }
                        }
                    }
                }
                else {
                    t.modrm = true;
                    t.reg_suf = true;
      
                }

                if (r.indexOf('//') != 0) {
                    r += `        .into_table(&mut ops);\n`;
                }

                if (t.Test() == 6) {
                    result += r;
                }
                else {
                    result += t.GetStatus();
                }
            }
            else if (group.length == 2 && group[0].args != '' && group[1].args != '') { //grouped opcode
                var args1 = group[0].args.split(','), args2 = group[1].args.split(',');
                var arg1group = `${args1[0]}+${args2[0]}`, arg2group;
                if (args1[1])
                    arg2group = `${args1[1]}+${args2[1]}`;
                
                var r = `    define_opcode(0x${group[0].opcode})`;

                t.extended = true;
                if (group[0].extended) {
                    r += '.is_extended()';
                }

                t.group_id = true;
                if (group[0].group_id != -1) {
                    r += `.is_group(${group[0].group_id})`;
                }

                r += `.calls(ops::${group[0].operation.toLowerCase()}).with_gas(GAS_PLACEHOLDER) \n`;
                
                //arg 1
                if (group[0].modrm_reg && this.ArgList['/r'][arg1group])
                    r += '        .' + this.ArgList['/r'][arg1group] + `\n`;
                else if (group[0].reg_suffix && this.ArgList['+r'][arg1group])
                    r += '        .' + this.ArgList['+r'][arg1group] + `\n`;
                else if (this.ArgList[arg1group])
                    r += '        .' + this.ArgList[arg1group] + `\n`;
                else {
                    var t_a = '';
                    for (arg in this.ArgList) {
                        if (arg.split('|').indexOf(args2[0]) != -1) {
                            t_a = this.ArgList[arg];
                        }
                    }
                    t_a = t_a.replace('{0}', args2[0]);

                    if (t_a.trim() == '') {
                        r = `//TODO - um wat?\n`
                    }
                    else {
                        r += '        .' + t_a + `\n`;
                    }
                }
                
                
                
                //arg 2

                
                
                
                if (r.indexOf('//') != 0) {
                    r += `        .into_table(&mut ops);\n`;
                }

               
               // result += r;

            }

            result += `\n`;
        }

        //console.log(lines);
        //console.log(ops);

        return result;
    },

    TestObj: function () {
        this.modrm = false;
        this.reg_suf = false;
        this.group = false;
        this.extended = false;
        this.args = false;
        this.group_id = false;
        this.Test = function () {
            return this.modrm + this.reg_suf + this.group + this.extended + this.args + this.group_id;
        }
        this.GetStatus = function () {
            return '//TODO - Not tested for: ' +
                [
                    (this.modrm ? undefined : 'modrm'),
                    (this.reg_suf ? undefined : 'reg_suffix'),
                    (this.group ? undefined : 'grouped opcode'),
                    (this.extended ? undefined : 'extended opcode'),
                    (this.args ? undefined : 'arguments'),
                    (this.group_id ? undefined : 'group id')
                ].filter(i => i != undefined).join(', ') + `\n`;
        }
    }


};