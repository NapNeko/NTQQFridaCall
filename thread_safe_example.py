import frida
import sys

def on_message(message, data):
    print(message)

def main():
    pid = frida.spawn(program="D:\\AppD\\QQNT\\QQ.exe", argv=["--enable-logging"])
    session = frida.attach(pid)
    frida.resume(pid)
    print(f"Attached to process {pid}")

    while True:
        with open("thread_safe_example.js", encoding="utf-8") as f:
            script = session.create_script(f.read())
            script.on("message", on_message)
            script.load()
        sys.stdin.readline()


if __name__ == "__main__":
    main()
