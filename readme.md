
# plugin feature

对于抓到的gb28181的rtp包，对ps封装的`ps`, `system`, `systme map`, `pes`等字段进行解析

## 使用方法

1. 保存`ps.lua`文件，放到wireshark(`linux:`/etc/wireshark)安装目录下，然后修改wireshark安装目录下的`init.lua`文件：
2. 若有`disable_lua = true`这样的行，则注释掉, 或者修改为`disable_lua = false`
3. 在`init.lua`文件末加入`dofile("ps.lua")`
4. 重新打开wirekshark,可以添加`ps`过滤协议进行过滤

## 注意

`DissectorTable.get`获取的时候，如果是解析`rtp`的报文，则协议在必须和sdp中的结构保持一致，
如此例程中的sdp为rtpmap为`PS`,则proto则必须定义为`PS`，否则无法解析到报文

## changed 2019-4-8

add the lua file and display fileds normally