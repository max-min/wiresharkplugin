--[[
    ps packet protocol 
]]
do

    local ps_proto = Proto("PS", "ps packet protolcol")

    --[[
        定义ps - system map - systemheader- pes结构字段
    --]]
    local psheader = ProtoField.uint32("PS.psheader", "Header[ps]", base.HEX)
    local pscontent = ProtoField.bytes("PS.pscontent", "Content[ps]", base.NONE)
    
    local sysheader = ProtoField.uint32("PS.sysheader", "Header[system]", base.HEX)
    local syslen = ProtoField.uint32("PS.syslen", "Lenght[system]", base.DEC)
    local syscontent = ProtoField.bytes("PS.syscontent", "Content[system]", base.NONE)

    local mapheader = ProtoField.uint32("PS.mapheader", "Header[systemmap]", base.HEX)
    local maplen = ProtoField.uint32("PS.maplen", "Length[systemmap]", base.DEC)
    local mapcontent = ProtoField.bytes("ps.mapcontent","Content[systemmap]", base.NONE)

    local pesheader = ProtoField.uint32("ps.pesheader", "Header[pes]", base.HEX)
    local peslen = ProtoField.uint32("ps.pesheader", "Lenght[pes]", base.DEC)
    local pescontent = ProtoField.bytes("ps.pescontent", "Content[pes]", base.NONE)
    local pesheaderlen = ProtoField.uint32("ps.pesheaderlen", "Length[pes]", base.DEC)

    local payloadlen = ProtoField.uint32("ps.payloadlength", "Lenght[payload]", base.DEC)
    local datapayload = ProtoField.bytes("ps.datapayload", "Payload", base.NODE)
    
    -- 将字段添加都协议中
    ps_proto.fields = {
        psheader,
        pscontent,
        sysheader,
        syslen,
        syscontent,
        mapheader,
        maplen,
        mapcontent,
        pesheader,
        peslen,
        pescontent,
        pesheaderlen,
        payloadlen,
        datapayload
    }
    
    --[[
        下面定义解析器的主函数，这个函数由 wireshark调用
        第一个参数是 Tvb 类型，表示的是需要此解析器解析的数据
        第二个参数是 Pinfo 类型，是协议解析树上的信息，包括 UI 上的显示
        第三个参数是 TreeItem 类型，表示上一级解析树
    --]]
    function ps_proto.dissector(tvb, pinfo, tree)
        
        pinfo.cols.protocol:set(ps_proto.name)
        pinfo.cols.info:set("PS Protocol")
        
        local offset = 0
        local tvb_len = tvb:len()
        
        local ps_tree = tree:add(ps_proto,  tvb:range(offset, tvb_len))  
            
        ps_tree:append_text(", ps packet,".."0x000001 ba,bb,bc,e0")
        --[[ 
            下面是想该根节点上添加子节点，也就是自定义协议的各个字段
            注意 range 这个方法的两个参数的意义，第一个表示此时的偏移量
            第二个参数代表的是字段占用数据的长度
        --]]
       
         --ps 
        local ps_type = tvb(offset, 4):uint()
        if (ps_type == 0x000001ba)
        then 
            ps_tree:add(psheader, tvb:range(offset,  4))
            offset = offset+4        
            ps_tree:add(pscontent,tvb:range(offset,  16))
            offset = offset+16
        end 
       
        -- system 
        local sys_type = tvb(offset, 4):uint()
        if (sys_type == 0x000001bb)
        then 
            ps_tree:add(sysheader,tvb:range(offset,  4))
            offset = offset+4
            ps_tree:add(syslen,tvb:range(offset, 2))
            local lens = tvb(offset, 2):uint()
            offset = offset+2

            ps_tree:add(syscontent, tvb:range(offset, lens))
            offset = offset + lens
        end 


        -- system map 
        local map_type = tvb(offset, 4):uint()
        if (map_type == 0x000001bc) 
        then 
            ps_tree:add(mapheader, tvb:range(offset,4))
            offset = offset + 4
            ps_tree:add(maplen, tvb:range(offset,2))
            local lens2 = tvb(offset, 2):uint()
            offset = offset + 2
            ps_tree:add(mapcontent, tvb:range(offset,lens2))
            offset = offset + lens2
        end 

        -- pes
        while( offset < tvb:len())
        do
            local pes_type = tvb(offset, 4):uint()
            if (pes_type == 0x000001e0 or pes_type == 0x000001c0)
            then 
                ps_tree:add(pesheader, tvb:range(offset,4))
                offset = offset + 4
                ps_tree:add(peslen, tvb:range(offset,2))
                local lens3 = tvb(offset, 2):uint()
                offset = offset +2 
                
                -- pes header length 
                offset = offset + 2
                ps_tree:add(pesheaderlen, tvb:range(offset,1))
                local peslens = tvb(offset,1):uint()
                offset = offset +1

                ps_tree:add(pescontent, tvb:range(offset,peslens))
                offset = offset + peslens
                local payloadlens = lens3 - (peslens+3)
                
                --ps_tree:add(payloadlen, payloadlens)
                if payloadlens > tvb:len() then 
                    ps_tree:add(datapayload, tvb:range(offset,tvb:len()- offset))
                    offset = tvb:len()
                else 
                    ps_tree:add(datapayload, tvb:range(offset,payloadlens))
                    offset = offset + payloadlens
                end 
                

            else 
                ps_tree:add(datapayload, tvb:range(offset, tvb:len()))
                offset = tvb:len()
            end 
        end 
       
    end
    
    -- 向 wireshark 注册协议插件被调用的条件 >= 96
    -- 添加的 proto必须和sdp中的rtpmap中的字段一致
    local udp_port_table = DissectorTable.get("rtp_dyn_payload_type")
    udp_port_table:add("PS", ps_proto)



    -- Find this feature in menu "Tools->"Export ps straem to h264 data"
    function export_ps_stream_to_h264 ()
        -- to export raw data stream
    end
    register_menu("Export ps straem to h264 data", export_ps_stream_to_h264, MENU_TOOLS_UNSORTED)
end
   
