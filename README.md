
## Prerequisites
Install packages `ptpython`  `rsa` and `requests`
```bash
pip install requests rsa ptpython
# or
python3 -m pip install requests rsa
```

## Features

- Simple command line syntax
- Cache login status (`stok`)
- Automatically renew token if expired
- Extensible, customizable
- Interactive shell

## Usage


```bash
$ ./mercury.py --help
usage: mercury.py [-c CONFIG] [-h HOST] [-u USERNAME] [-p PASSWORD] [-d]
                  [--help]
                  [camera] {interactive,send,presets,goto,mask} ...

positional arguments:
  camera                Specify the Camera to use. default: cmdline
  {interactive,send,presets,goto,mask}
                        Functions to call
  action_args           Function arguments

optional arguments:
  -c CONFIG, --config CONFIG
                        config file to read IPC endpoints
  -h HOST, --host HOST  Camera web interface URL
  -u USERNAME, --username USERNAME
                        Camera admin username
  -p PASSWORD, --password PASSWORD
                        Camera admin password
  -d, --debug           Print additional debug logs
  --help                RT

```

## Commands

### send

There are two options.

1. the predefined payloads inside [mercury.py](https://github.com/ttimasdf/mercury-ipc-control/blob/97b0cec989db2406b4f8a698a15f734e2861aed1/mercury.py#L159-L205).

   ```bash
   ./mercury.py ipc1 send PAYLOAD_SET_LED_OFF
   ```

2. Send payload string directly.

   ```bash
   ./mercury.py ipc1 send "{'method': 'do', 'preset': {'goto_preset': {'id': '1'}}}"
   ```

### presets

Print presets config of specific camera. Preset ID and name is ordered by create time, NOT numeric, NOT necessarily start from 1.

```bash
$ ./mercury.py ipc1 presets
INFO     sendRequest  Sending request: {'method': 'get', 'preset': {'name': ['preset']}}

Presets: 
2  面壁        

INFO     main         Saving configs back
INFO     main         Bye

```

### goto

Goto saved location with numeric ID.

```bash
./mercury.py ipc1 goto 2
```

### mask

Set lens mask on or off:

```bash
./mercury.py ipc1 mask on  # or off
```

Get mask status, invoke with no parameter.

```bash
$ ./mercury.py ipc1 mask
INFO     sendRequest  Sending request: {'method': 'get', 'lens_mask': {'name': ['lens_mask_info']}}
INFO     main         Lens mask is OFF
INFO     main         Saving configs back
INFO     main         Bye
```

## Interactive mode

After logged in, you'll get an interactive shell. Requires `ptpython`.

You could e.g. send your payload data to `mer.sendRequest`.

```bash
$ ./mercury.py ipc1 interactive
INFO     login        Retrive RSA Pubkey and Nonce
DEBUG    login        Response: 200 {'error_code': -40401, 'data': {'code': -40410, 'encrypt_type': ['1', '2'], 'key': 'MIGf<redacted>iwIDAQAB', 'nonce': '3f<redacted>0'}}
DEBUG    login        Encrypted password: J+WJ2<redacted>sv4=
INFO     login        Login with username [admin]
DEBUG    login        Login response: 200 {'error_code': 0, 'stok': '9fafab<redacted>6dfec', 'user_group': 'root'}
DEBUG    <module>     <__main__.MercuryIPC object at 0x1065c77d0>
INFO     <module>     Mercury IPC is available at variable [cam], fire at will ;p

>>> cam.send_request(cam.PAYLOAD_SET_LENMASK_ON)
DEBUG    send_request Sending request: {'method': 'set', 'lens_mask': {'lens_mask_info': {'enabled': 'on'}}}
DEBUG    send_request Response: 200 {'error_code': 0}
<Response [200]>

>>> cam.send_request({"method":"do","preset":{"goto_preset": {"id": "3"}}})
DEBUG    send_request Sending request: {'method': 'do', 'preset': {'goto_preset': {'id': '3'}}}
DEBUG    send_request Response: 200 {'error_code': 0}
<Response [200]>

```



## Data Example

```json
// add PTZ preset position 添加预置点
{"method":"do","preset":{"set_preset":{"name":"name","save_ptz":"1"}}}

// PTZ to preset position 转动到预置点
{"method":"do","preset":{"goto_preset": {"id": "1"}}}

// PTZ by coord 按坐标转动
{"method":"do","motor":{"move":{"x_coord":"10","y_coord":"0"}}}

// PTZ horizontal by step 水平步进
{"method":"do","motor":{"movestep":{"direction":"0"}}}

// PTZ vertical by step 垂直步进
{"method":"do","motor":{"movestep":{"direction":"90"}}}

// stop PTZ 停止步进
{"method":"do","motor":{"stop":"null"}}

//reset PTZ 云台重置
{"method":"do","motor":{"manual_cali":"null"}}

// lens mask 镜头遮蔽
{"method":"set","lens_mask":{"lens_mask_info":{"enabled":"on"}}}

// manual alarm 手动报警
{"method":"do","msg_alarm":{"manual_msg_alarm":{"action":"start"}}}
{"method":"do","msg_alarm":{"manual_msg_alarm":{"action":"stop"}}}

// toggle green led 绿色led开关
{"method":"set","led":{"config":{"enabled":"off"}}}
{"method":"set","led":{"config":{"enabled":"on"}}}

//auto track moving obj 智能追踪 摄像机追随移动物体
{"method":"set","target_track":{"target_track_info":{"enabled":"on"}}}
{"method":"set","target_track":{"target_track_info":{"enabled":"off"}}}

//alarm if found moving obj 检测到移动物体时报警
{"method":"set","msg_alarm":{"chn1_msg_alarm_info":{"enabled":"on","alarm_type":"0","alarm_mode":["sound"]}}}
{"method":"set","msg_alarm":{"chn1_msg_alarm_info":{"enabled":"on","alarm_type":"0","alarm_mode":["light"]}}}
{"method":"set","msg_alarm":{"chn1_msg_alarm_info":{"enabled":"on","alarm_type":"0","alarm_mode":["sound","light"]}}}
{"method":"set","msg_alarm_plan":{"chn1_msg_alarm_plan":{"enabled":"on","alarm_plan_1":"0000-0000%2c127"}}}

//motion detection 移动侦测 与 侦测灵敏度
{"method":"set","motion_detection":{"motion_det":{"enabled":"off"}}}
{"method":"set","motion_detection":{"motion_det":{"enabled":"on"}}}
{"method":"set","motion_detection":{"motion_det":{"digital_sensitivity":"20"}}}
{"method":"set","motion_detection":{"motion_det":{"digital_sensitivity":"50"}}}
{"method":"set","motion_detection":{"motion_det":{"digital_sensitivity":"80"}}}

//enable record and plan 是否录制与录制计划
{"method":"set","record_plan":{"chn1_channel":{"enabled":"off","monday":"%5b%220000-2400%3a2%22%5d","tuesday":"%5b%220000-2400%3a2%22%5d","wednesday":"%5b%220000-2400%3a2%22%5d","thursday":"%5b%220000-2400%3a2%22%5d","friday":"%5b%220000-2400%3a2%22%5d","saturday":"%5b%220000-2400%3a2%22%5d","sunday":"%5b%220000-2400%3a2%22%5d"}}}
{"method":"set","record_plan":{"chn1_channel":{"enabled":"on","monday":"%5b%220000-2400%3a2%22%5d","tuesday":"%5b%220000-2400%3a2%22%5d","wednesday":"%5b%220000-2400%3a2%22%5d","thursday":"%5b%220000-2400%3a2%22%5d","friday":"%5b%220000-2400%3a2%22%5d","saturday":"%5b%220000-2400%3a2%22%5d","sunday":"%5b%220000-2400%3a2%22%5d"}}}

//reboot and timing reboot 重启与定时重启
{"method":"do","system":{"reboot":"null"}}
{"method":"set","timing_reboot":{"reboot":{"enabled":"off","day":"7","time":"03%3a00%3a00"}}}
{"method":"set","timing_reboot":{"reboot":{"enabled":"on","day":"7","time":"03%3a00%3a00"}}}

//greetings 个性语音提示
{"method":"set","greeter":{"chn1_greeter_ctrl":{"enabled":"on"}}}
{"method":"set","greeter":{"chn1_greeter_ctrl":{"enabled":"off"}}}
//greeting volume 音量
{"method":"set","greeter":{"chn1_greeter_audio":{"enter_volume":"77","leave_volume":"77"}}}
//play greetings 播放语音
{"method":"do","greeter":{"test_audio":{"force":"1"}}} 播放默认语音
{"method":"do","greeter":{"test_audio":{"id":"4096","force":"1"}}} 播放指定语音
//id
//0 无
//12288 你好
//4096-4104 依次为 你好欢迎光临 .....
//set enter or leave greetings 设置进入或离开语音
{"method":"set","greeter":{"chn1_greeter_audio":{"enter_audio_id":"0"}}} 无
{"method":"set","greeter":{"chn1_greeter_audio":{"leave_audio_id":"4104"}}}
```

ref: http://blog.xiazhiri.com/Mercury-MIPC251C-4-Reverse.html