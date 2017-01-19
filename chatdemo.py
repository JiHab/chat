from _md5 import md5
import logging
import tornado.escape
import tornado.ioloop
import tornado.web
import os.path
import uuid
from Crypto.Cipher import AES
from pycr import enc
from tornado.concurrent import Future
from tornado import gen
from tornado.options import define, options, parse_command_line

define("port", default=8888, help="run on the given port", type=int)
define("debug", default=False, help="run in debug mode")

# создаем буфер для хранения сообщений
class MessageBuffer(object):
    def __init__(self):
        self.waiters = set()
        self.cache = []
        self.cache_size = 200
    def wait_for_messages(self, cursor=None):
        result_future = Future()
        if cursor:
            new_count = 0
            for msg in reversed(self.cache):
                if msg["id"] == cursor:
                    break
                new_count += 1
            if new_count:
                result_future.set_result(self.cache[-new_count:])
                return result_future
        self.waiters.add(result_future)
        return result_future

    def cancel_wait(self, future):
        self.waiters.remove(future)
        future.set_result([])

    def new_messages(self, messages):
        logging.info("Sending new message to %r listeners", len(self.waiters))
        for future in self.waiters:
            future.set_result(messages)
        self.waiters = set()
        self.cache.extend(messages)
        if len(self.cache) > self.cache_size:
            self.cache = self.cache[-self.cache_size:]


global_message_buffer = MessageBuffer()


class BaseHendler(tornado.web.RequestHandler):
    def get_current_user(self):
       return self.set_cookie('user')


class Enter(tornado.web.RequestHandler):
    def get(self):
        #тут вводим ключ
        self.render("enter.html")


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        #записываем ключ в куки
        self.set_secure_cookie('key', self.get_argument('key'))
        # key = self.get_secure_cookie('key')
        # print('on index key:', key)
        self.render("index.html", messages=global_message_buffer.cache)


class MessageNewHandler(tornado.web.RequestHandler):
    def post(self):

        body = self.get_argument("body")
        #получаем ключ из куки
        key = self.get_secure_cookie('key')
        #создаем екземпляр класса и шифруем
        enc_obj = Encryption(data=body, key=key)
        enc_data = enc_obj.encrypt()
        # print(enc_data)
        # print(str(enc_data))
        #print(len(str(enc_data)))
        #передаем в буфер шифрованные сообщения
        message = {
            "id": str(uuid.uuid4()),
            'body': str(enc_data)
        }
        #себе выводим не шифрованое
        message_to_render = {
            "id": str(uuid.uuid4()),
            "body": body,
        }

        message["html"] = tornado.escape.to_basestring(
            self.render_string("message.html", message=message_to_render))
        if self.get_argument("next", None):
            self.redirect(self.get_argument("next"))
        else:
            self.write(message)
        global_message_buffer.new_messages([message])


class MessageUpdatesHandler(tornado.web.RequestHandler):
    @gen.coroutine
    def post(self):
        cursor = self.get_argument("cursor", None)
        self.future = global_message_buffer.wait_for_messages(cursor=cursor)
        #получаем сообщения из буфера
        messages = yield self.future
        #получаем ключ из куки
        key = self.get_secure_cookie('key')
        enc_obj = Encryption(key=key)
        #расшифровываем сообщения из из буфера
        for message in messages:
            # шифрованый текст сообщений хранятся в буфере в словаре типа {"body": "b'\\x0eT@\\xca,3\\xf0'"}
            # много времени убил на декодирование байтов преобразованных в строку функцией str() изза бекслешей
            # идем по пути наименьшего сопротивления, хоть так делать и нельзя
            data = eval(message['body'], {})
            message['body'] = enc_obj.decrypt(data=data).decode()
        if self.request.connection.stream.closed():
            return
        self.write(dict(messages=messages))

    def on_connection_close(self):
        global_message_buffer.cancel_wait(self.future)


def main():
    parse_command_line()
    app = tornado.web.Application(
        [
            (r"/", Enter),
            (r"/chat", MainHandler),
            (r"/a/message/new", MessageNewHandler),
            (r"/a/message/updates", MessageUpdatesHandler),
            ],
        cookie_secret="123123",
        template_path=os.path.join(os.path.dirname(__file__), "templates"),
        static_path=os.path.join(os.path.dirname(__file__), "static"),
        xsrf_cookies=True,
        debug=True,
        )
    app.listen(options.port)
    tornado.ioloop.IOLoop.current().start()


class Encryption(object):
    def __init__(self, data=None, key=None):
        self.data = data
        # как ключ вводим любые символы, 128 битный генерируем хешированием
        self.key = md5(key).digest()
        # с вектором особо не заморачиваемся, можно его создавать, путем отсекания 16 байт из ключа
        self.iv = 16 * '\x00'
        self.mode = AES.MODE_CFB

    def encrypt(self, data=None):
        if not data:
            data = self.data
        ciphered = AES.new(self.key, self.mode, self.iv).encrypt(data)
        return ciphered

    def decrypt(self, data=None):
        if not data:
            data = self.data
        de_ciphered = AES.new(self.key, self.mode, self.iv).decrypt(data)
        return de_ciphered


if __name__ == "__main__":
    main()
