from modbus_tk import modbus_tcp
import modbus_tk.defines as cst
import modbus_tk
import time

def main():
    startTime = time.time()
    master = modbus_tcp.TcpMaster("192.168.163.150", 502)
    for i in range(10):
        try:
            data = master.execute(slave=1, function_code=cst.READ_INPUT_REGISTERS, starting_address=0, quantity_of_x=3)
            print(data)
            print("Humidity :", format(float(data[0])/float(100),'.2f'))
            print("Temperature (Celsius) :", format(float(data[1])/float(100),'.2f'))
            print("Temperature (Fahrenheit) :", format(float(data[2])/float(100),'.2f'))
        except modbus_tk.modbus.ModbusError as exc:
            print("%s- Code=%d", exc, exc.get_exception_code())
        except modbus_tcp.ModbusInvalidMbapError as exc:
            print(exc)
        time.sleep(0.1)
    endTime = time.time()
    print(endTime - startTime)

if __name__ == '__main__':
    main()