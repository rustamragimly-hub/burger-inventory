from flask import Flask, request, render_template_string, send_file, jsonify, redirect, session
from threading import Lock
from openpyxl import Workbook
from werkzeug.security import generate_password_hash, check_password_hash
import io
from datetime import datetime
import secrets
import os

app = Flask(__name__)

@app.route("/")
def index():
    return redirect("/login")


app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Данные хранилища
inventory = {}
history = {}
users = {"admin": {"password": generate_password_hash("admin123"), "role": "admin"}}
pending_finish = {}
inventory_lock = Lock()
users_lock = Lock()

# ПОЛНЫЙ СЛОВАРЬ ТОВАРОВ (378 позиций)
GLOBAL_PRODUCTS = {
    "Алкоголь - Вино": {
        "Ноче де Луна брют игр белое 0,75": {"unit": "л", "code": 5457},
        "Вино игристое Боттега Просекко Розе брют 0,2": {"unit": "гр.", "code": 4233},
        "Вино игристое Абрау Дюрсо брют 0,375": {"unit": "гр.", "code": 4313},
        "Вино красное  Темпранильо сухое 0,187": {"unit": "л", "code": 5425},
        "Вино белое Пино Гриджио сухое 0,75": {"unit": "л", "code": 4064},
        "Вино красное Кьянти сухое 0,75": {"unit": "шт.", "code": 4069},
        "Вино белое  Совиньон Блан сухое 0,187": {"unit": "л", "code": 4066},
        "Вино белое  Пино Гриджио сухое 0,75 молодое": {"unit": "л", "code": 4369},
        "Вино белое  Рислинг Кубань сухое 0,75": {"unit": "л", "code": 4065},
        "Вино белое  Совиньон Блан сухое 0,75": {"unit": "л", "code": 5421},
        "Вино белое  Шардоне Гуд Стейк кубань сухое 0,187": {"unit": "л", "code": 4067},
        "Вино белое Георг Штайнмец РИСЛИНГ 0,75": {"unit": "л", "code": 4239},
        "Вино игр Режи брют белое 0,75": {"unit": "л", "code": 5440},
        "Вино игристое Бруни Просекко брют белое": {"unit": "л", "code": 4371},
        "Вино игристое Девико белое брют 0,75": {"unit": "л", "code": 4862},
        "Вино красное  Мерло сухое 0,75": {"unit": "л", "code": 4070},
        "Вино красное  Примитиво   сухое 0,187": {"unit": "шт.", "code": 4071},
        "Вино красное  Шираз  сухое 0,187": {"unit": "шт.", "code": 4072},
        "Вино розовое Гренаш-Сенсо 0,187  п/сух": {"unit": "гр.", "code": 4230},
        "Вино розовое Зинфандель п/сл  0,187": {"unit": "л", "code": 4068},
        "Ганча Асти сл бел игристое 0,2": {"unit": "л", "code": 4073},
        "Делиссимо белое брют 0,25": {"unit": "л", "code": 4074},
        "Делиссимо белое брют 0,75": {"unit": "л", "code": 4075},
        "Делиссимо белое п/сл 0,25": {"unit": "л", "code": 4076},
        "Делиссимо розовое брют 0,25": {"unit": "л", "code": 4077},
        "Делиссимо розовое п/сл 0,25": {"unit": "л", "code": 4078},
        "Кювэ Даржен  брют игр белое 0,75": {"unit": "л", "code": 4922},
        "Проссеко Гаэтано экстра драй 0,2": {"unit": "шт.", "code": 4079},
        "Тинтонелли Просекко экстра драй 0,75": {"unit": "л", "code": 4082},
        "Фиорино д*Оро Брют игр бел": {"unit": "л", "code": 4080},
        "Франсуа Блан де Блан сух 0,2": {"unit": "л", "code": 4081},
        "Шато де ля Мер  брют игр белое 0,75": {"unit": "л", "code": 4279},
        "Вино игристое Боттега Голд Просекко брют 0,2": {"unit": "л", "code": 4232},
        "Вино игристое Абрау Дюрсо розе  0,375": {"unit": "гр.", "code": 4483},
    },
    "Алкоголь - Крепкое": {
        "Виски Вудфорд Резерв 0,75": {"unit": "шт.", "code": 4009},
        "Виски Гленморанджи Ориджинал бут 0,05": {"unit": "шт.", "code": 4010},
        "Виски Гленфиддик 12 лет": {"unit": "л", "code": 4011},
        "Виски Гленфиддик 12 лет бут 0,05": {"unit": "шт.", "code": 4231},
        "Виски Грантс Трипл Вуд 3 г": {"unit": "л", "code": 4012},
        "Виски Джек Дениэлс бут 0,05": {"unit": "шт.", "code": 4136},
        "Виски Джек Дениэлс 1л": {"unit": "л", "code": 4013},
        "Виски Джек Дэниел*с Файер 0,7": {"unit": "л", "code": 4014},
        "Виски Джек Дэниел*с Хани 0,7": {"unit": "л", "code": 4015},
        "Виски Джемесон 1л": {"unit": "л", "code": 4016},
        "Виски Джентельмен Джек Рэар Тенн. бут 0,05": {"unit": "шт.", "code": 4017},
        "Виски Ирли Таймс Олд": {"unit": "л", "code": 4018},
        "Виски Лэнгс Смус энд Меллоу 0,7": {"unit": "л", "code": 4376},
        "Виски Мэйкерс Марк 0,7": {"unit": "шт.", "code": 4019},
        "Виски Синглтон 12 лет бут 0,2": {"unit": "шт.", "code": 4020},
        "Виски Талмор ДИУ 3 г бут 0,05": {"unit": "шт.", "code": 4021},
        "Виски Талмор ДИУ 3 года": {"unit": "л", "code": 4022},
        "Водка Байкал": {"unit": "л", "code": 4023},
        "Водка Байкал Айс": {"unit": "л", "code": 4024},
        "Водка Белуга Золотая линия 0,75": {"unit": "л", "code": 4028},
        "Водка Белуга нобл": {"unit": "л", "code": 4029},
        "Водка Белуга нобл бут 0,05": {"unit": "шт.", "code": 4030},
        "Водка Нерпа Органик 0,7": {"unit": "шт.", "code": 4033},
        "Водка Онегин бут 0,05": {"unit": "шт.", "code": 4364},
        "Водка Онегин": {"unit": "шт.", "code": 4367},
        "Водка Финляндия": {"unit": "л", "code": 4034},
        "Водка Финляндия Грейпфрут": {"unit": "л", "code": 4035},
        "Водка Царская Золотая": {"unit": "л", "code": 4036},
        "Водка Царская Золотая бут 0,05": {"unit": "шт.", "code": 4037},
        "Водка Царская оригинальная": {"unit": "л", "code": 4038},
        "Водка Царская оригинальная бут 0,05": {"unit": "шт.", "code": 4039},
        "Водка Чача отборная бут 0,1": {"unit": "шт.", "code": 4342},
        "Джин Барристер Драй бут 0,05": {"unit": "шт.", "code": 4040},
        "Джин Барристер Олд Том бут 0,05": {"unit": "шт.", "code": 4041},
        "Джин Гленс Джин 0,7": {"unit": "л", "code": 4042},
        "Джин Грин Бабун 0,7": {"unit": "гр.", "code": 4043},
        "Джин Дип Форест Джин Драй  0,5": {"unit": "шт.", "code": 4044},
        "Джин Локвуд Ориджинал Драй  0,5": {"unit": "л", "code": 5458},
        "Джин Лондон Драй джин  0,7": {"unit": "л", "code": 4045},
        "Джин Маре бут 0,05": {"unit": "шт.", "code": 4368},
        "Коньяк АНИ КВ (7 лет) 0,05 бут": {"unit": "шт.", "code": 4046},
        "Коньяк АНИ КВ (7 лет) 0,25 бут": {"unit": "шт.", "code": 4047},
        "Коньяк АНИ КВ (7 лет) 0,5 бут": {"unit": "шт.", "code": 4048},
        "Коньяк Арарат 5 зв бут 0,05": {"unit": "шт.", "code": 5424},
        "Коньяк Арарат 5 зв бут 0,250": {"unit": "шт.", "code": 4054},
        "Коньяк Аророт 5 зв. 1л": {"unit": "л", "code": 4055},
        "Коньяк Ахтамар КС (10 лет) 0,05": {"unit": "л", "code": 4049},
        "Коньяк Камю ВС 3 года 0,7": {"unit": "шт.", "code": 4373},
        "Коньяк Камю ВСОП 4 года 0,7": {"unit": "шт.", "code": 4050},
        "Коньяк Курвуазье ХО 0,7": {"unit": "шт.", "code": 4051},
        "Коньяк МОННЕ ВС 0,05 бут 3 года": {"unit": "шт.", "code": 4372},
        "Коньяк Хеннесси ВСОП привълж бут 0,05": {"unit": "шт.", "code": 4052},
        "Коньяк Хеннесси ХО 0,7": {"unit": "шт.", "code": 4053},
        "Ром Барсело Аньехо": {"unit": "л", "code": 4058},
        "Ром Барсело Бланко": {"unit": "л", "code": 4059},
        "Ром Болье Блан 0,7": {"unit": "л", "code": 5419},
        "Ром Болье Голд 0,7": {"unit": "л", "code": 5420},
        "Ром Рон Каладос Уайт  н/выдерж 0,7": {"unit": "л", "code": 4374},
        "Текила Рустер Рохо Бланко  0,7": {"unit": "л", "code": 4375},
        "Текила Эль Бандидо Негро Бланко 0,7": {"unit": "л", "code": 4060},
        "Текила Эль Бандидо Негро Голд 0,7": {"unit": "л", "code": 4061},
        "Текила Эль Химадор  Репосадо": {"unit": "л", "code": 4062},
    },
    "Алкоголь - Пиво": {
        "Аббе брюн 0,33 л": {"unit": "л", "code": 4090},
        "Бон Сезон сидр 0,4": {"unit": "шт.", "code": 4096},
        "Гиннесс Драфт тёмн 0,44л": {"unit": "л", "code": 4091},
        "Корона экстра 0,355 л": {"unit": "л", "code": 5571},
        "Пиво СТАУТ тёмн фильтр 30л": {"unit": "л", "code": 4085},
        "Пиво ФРАНЦИСКАНЕР 30л": {"unit": "л", "code": 4087},
        "Пиво ШПАТЕН Мюнхен Хеллес 30л": {"unit": "л", "code": 4089},
        "Стелла Артуа 20л": {"unit": "л", "code": 4086},
        "Стелла Артуа б/а 0,44": {"unit": "л", "code": 4092},
        "Хугарден  белое н/ф 0,44": {"unit": "л", "code": 4093},
        "Шпатен Мюнхен Хеллнс 0.45": {"unit": "л", "code": 4095},
    },
    "Алкоголь - Прочее": {
        "Вермут Ганча Бьянко 1,0": {"unit": "шт.", "code": 4006},
        "Вермут Ганча Россо 1,0": {"unit": "шт.", "code": 4007},
        "Вермут Ганча Экстра Драй 1,0": {"unit": "шт.", "code": 4008},
        "Вермут Мартини Фиеро 1,0": {"unit": "шт.", "code": 4287},
        "Ликёр Айриш Крим 0,7": {"unit": "л", "code": 4370},
        "Ликёр Белуга Хантинг тр. бут 0,05": {"unit": "шт.", "code": 4031},
        "Ликёр Белуга Хантинг травяной": {"unit": "л", "code": 4032},
        "Ликёр Ягермайстер": {"unit": "л", "code": 4056},
        "Ликёр Ягермайстер бут 0,04 мл": {"unit": "шт.", "code": 4057},
        "Мартини Розато 0,25": {"unit": "шт.", "code": 4285},
        "Мартини Секко 0,25": {"unit": "шт.", "code": 4284},
        "Мартини Семи Дольче 0,25": {"unit": "л", "code": 4286},
        "Настойка Байкал -Северная тропа Клюква 0,5": {"unit": "л", "code": 4025},
        "Настойка Байкал Мёд с перцем 0,5": {"unit": "л", "code": 4026},
        "Настойка Байкал на кедр. орешках 0,5": {"unit": "л", "code": 4027},
        "Настойка Онегин гурмэ вишня 0,5": {"unit": "шт.", "code": 4366},
        "Настойка Онегин гурмэ курага 0,5": {"unit": "шт.", "code": 4365},
        "Портвейн Агдам белый 0,75": {"unit": "л", "code": 4314},
    },
    "Готовые блюда": {
        "Вареники в асс": {"unit": "шт.", "code": 4224},
        "Кур, филе маринованное п/ф с/м 0,16": {"unit": "л", "code": 3941},
        "Наггетсы в кляре": {"unit": "л", "code": 3942},
        "Пельмени": {"unit": "л", "code": 3961},
        "Сэндвич ветчина сыр": {"unit": "шт.", "code": 5542},
        "Сэндвич с курицей": {"unit": "шт.", "code": 5541},
        "Сырники п/ф 70g": {"unit": "кг", "code": 3921},
    },
    "Кофе/Сиропы": {
        "Кофе б/р": {"unit": "шт.", "code": 3956},
        "Кофе зерно 0,25кг": {"unit": "кг", "code": 3836},
        "Сироп ваниль 1л": {"unit": "л", "code": 3837},
        "Сироп карамель 1л": {"unit": "л", "code": 3838},
        "Сироп лесной орех 1л": {"unit": "л", "code": 3839},
        "Сироп шоколад 1л": {"unit": "л", "code": 3840},
    },
    "Крупы/Макароны": {
        "Гречка": {"unit": "гр.", "code": 3955},
        "Лапша пшеничная 300g": {"unit": "л", "code": 3830},
        "Макароны": {"unit": "шт.", "code": 3959},
        "Манка": {"unit": "шт.", "code": 3957},
        "Перловка": {"unit": "л", "code": 3962},
        "Рис": {"unit": "шт.", "code": 3964},
        "Хлопья геркулес": {"unit": "л", "code": 3833},
    },
    "Масла": {
        "Майонез Хелманс 4,7кг": {"unit": "кг", "code": 3905},
        "Масло белый трюфель оливковое": {"unit": "л", "code": 3899},
        "Масло кунжутное 1,8л": {"unit": "л", "code": 3900},
        "Масло оливковое": {"unit": "л", "code": 3901},
        "Масло растительное": {"unit": "л", "code": 3902},
        "Масло сливочное 0,5кг": {"unit": "кг", "code": 3906},
        "Масло фритюрное": {"unit": "л", "code": 3903},
        "Отработка фритюр": {"unit": "шт.", "code": 3904},
    },
    "Молочное": {
        "Молоко 3,2% 1л": {"unit": "л", "code": 3907},
        "Молоко банановое 1л": {"unit": "л", "code": 3908},
        "Молоко безлактозное 1л": {"unit": "л", "code": 3909},
        "Молоко кокосовое 1л": {"unit": "л", "code": 3910},
        "Молоко соевое 1л": {"unit": "л", "code": 3911},
        "Сиртаки сыр, брынза 0,33": {"unit": "шт.", "code": 3912},
        "Сливки 10-11%": {"unit": "л", "code": 3913},
        "Сливки 22% 1л": {"unit": "л", "code": 3914},
        "Сметана 20% 1кг": {"unit": "кг", "code": 3915},
        "Сыр Пармезан крошка 1,0кг": {"unit": "кг", "code": 3916},
        "Сыр Сулугуни копчёный 0,4кг": {"unit": "кг", "code": 3918},
        "Сыр Чеддар": {"unit": "шт.", "code": 3920},
        "Сыр с плесенью": {"unit": "л", "code": 3917},
        "Сыр творожный сливочный 1,0кг": {"unit": "кг", "code": 3919},
        "Сырные палочки": {"unit": "л", "code": 3922},
    },
    "Мясо": {
        "Бедро куриное с/м": {"unit": "шт.", "code": 5411},
        "Бекон копчёный 1,0кг": {"unit": "кг", "code": 3855},
        "Ветчина с/п": {"unit": "шт.", "code": 4762},
        "Говядина сп": {"unit": "шт.", "code": 4761},
        "Колбаски в асс": {"unit": "л", "code": 4083},
        "Колбаски говяжьи п/ф": {"unit": "л", "code": 4593},
        "Котлета вега для бургера 110g": {"unit": "л", "code": 3895},
        "Котлета говяжья 150g": {"unit": "л", "code": 3896},
        "Котлета куриная для бургера 130g": {"unit": "л", "code": 3898},
        "Крылья куриные в маринаде 0,92кг": {"unit": "кг", "code": 3940},
        "Куры, голень, бедро, крыло, филе с/п": {"unit": "л", "code": 3958},
        "Свинина с/п": {"unit": "шт.", "code": 3965},
        "Сосиски с/п": {"unit": "шт.", "code": 3966},
        "Стейк Рибай кг": {"unit": "кг", "code": 4867},
        "Стейк Рибай, порции": {"unit": "шт.", "code": 3944},
        "Стейк стриплойн с/м": {"unit": "л", "code": 3943},
        "Фарш персонал": {"unit": "л", "code": 3968},
        "Фарш говяжий кг": {"unit": "кг", "code": 4855},
    },
    "Напитки": {
        "Адреналин Раш энергетик": {"unit": "л", "code": 3987},
        "Аква минерале 2,0л": {"unit": "л", "code": 4147},
        "Вода Прана Спринг 0,5": {"unit": "шт.", "code": 5403},
        "Вода Боржоми (ПЭТ) 0,5л": {"unit": "л", "code": 3988},
        "Вода Кристель с/г 0,33л": {"unit": "л", "code": 3994},
        "Вода Святой источник (ПЭТ) 0,5л": {"unit": "л", "code": 3999},
        "Вода детская 0,33л": {"unit": "шт.", "code": 3989},
        "Вода с/газ д/коктейля 0,5л": {"unit": "л", "code": 3990},
        "Какао": {"unit": "шт.", "code": 3835},
        "Какаолат Мокко 0,2л": {"unit": "л", "code": 5536},
        "Какаолат ПЭТ 0,2л": {"unit": "л", "code": 5534},
        "Какаолат без/сахара 0,2л": {"unit": "л", "code": 5533},
        "Какаолат стекло 0,2л": {"unit": "л", "code": 5535},
        "Кока-Кола (оригинал) 0,33л": {"unit": "л", "code": 5406},
        "Кока-Кола (оригинал) 0,5л": {"unit": "л", "code": 3993},
        "Конфеты Малина в шоколаде": {"unit": "л", "code": 4959},
        "Лимонад Груша-размарин": {"unit": "л", "code": 4004},
        "Лимонад Манго-перцы": {"unit": "л", "code": 3996},
        "Лимонад домашний (лимон-лайм)": {"unit": "л", "code": 3995},
        "Лимонад смородина-базилик": {"unit": "л", "code": 3997},
        "Лимонады 0,33л асс": {"unit": "л", "code": 4771},
        "Лимонады 0,5л асс": {"unit": "л", "code": 3991},
        "Пивной напиток ХУГАРДЕН 20л": {"unit": "л", "code": 4088},
        "Пятый Океан св фильтр 30л": {"unit": "л", "code": 4135},
        "Сан Бенедетто в асс 0,33л": {"unit": "шт.", "code": 4407},
        "Сахарный песок": {"unit": "шт.", "code": 3869},
        "Сок в ассорт 0,3+0,2л": {"unit": "шт.", "code": 4000},
        "Спиртной напиток Апероль 1л": {"unit": "л", "code": 4005},
        "Спрайт 0,5л": {"unit": "л", "code": 4001},
        "Тоник": {"unit": "шт.", "code": 4002},
        "Тоник 0,33л": {"unit": "шт.", "code": 5520},
        "Фанта 0,5л": {"unit": "л", "code": 4003},
        "Фильтр-пакет для чая": {"unit": "л", "code": 3841},
        "Чай в пакетиках д/персонала": {"unit": "л", "code": 3970},
        "Чай зелёный листовой 0,25кг": {"unit": "кг", "code": 3842},
        "Чай травяной 0,25кг": {"unit": "кг", "code": 3844},
        "Чай холодный в асс 0,5л": {"unit": "л", "code": 3998},
        "Чай чёрный листовой 0,25кг": {"unit": "кг", "code": 3843},
        "Черная мамба 0,5л": {"unit": "шт.", "code": 4094},
        "Шоколад в асс": {"unit": "л", "code": 3894},
    },
    "Овощи": {
        "Батат 2,5кг": {"unit": "кг", "code": 3934},
        "Водоросли нори 100листов": {"unit": "л", "code": 3923},
        "Капуста б/к": {"unit": "шт.", "code": 3971},
        "Картофель св кг": {"unit": "кг", "code": 3972},
        "Картофель фри с/м кг": {"unit": "кг", "code": 3935},
        "Кукуруза консервированная": {"unit": "шт.", "code": 4957},
        "Кукуруза початки": {"unit": "шт.", "code": 3936},
        "Лук конфи п/ф": {"unit": "л", "code": 3932},
        "Лук копченый п/ф": {"unit": "л", "code": 3933},
        "Лук красный репчатый": {"unit": "л", "code": 3974},
        "Лук репчатый": {"unit": "л", "code": 3973},
        "Маслины 0,09кг": {"unit": "кг", "code": 3926},
        "Маслины вяленые 0,4кг": {"unit": "кг", "code": 3927},
        "Микс салат 0,125кг": {"unit": "кг", "code": 3975},
        "Морковь по-корейски": {"unit": "шт.", "code": 4583},
        "Морковь свежая": {"unit": "шт.", "code": 3976},
        "Мята свежая": {"unit": "шт.", "code": 3977},
        "Огурцы марин кольца 1,0кг": {"unit": "кг", "code": 3928},
        "Огурцы свежие": {"unit": "шт.", "code": 3978},
        "Перец болгарский": {"unit": "л", "code": 4548},
        "Перец запеченный 2,5кг": {"unit": "кг", "code": 3929},
        "Перец красный острый": {"unit": "шт.", "code": 4408},
        "Перец порционный 1g": {"unit": "шт.", "code": 3861},
        "Перец халапеньо 1,5кг": {"unit": "кг", "code": 3930},
        "Перец черный дробленый": {"unit": "л", "code": 3862},
        "Перец черный молотый": {"unit": "л", "code": 3863},
        "Петрушка свежая": {"unit": "шт.", "code": 3979},
        "Петрушка сухая": {"unit": "шт.", "code": 3963},
        "Помидоры св кг": {"unit": "кг", "code": 3980},
        "Помидоры черри 0,25кг": {"unit": "кг", "code": 3981},
        "Салат Айсберг": {"unit": "л", "code": 3982},
        "Салат из водорослей чука 1,0кг": {"unit": "кг", "code": 3925},
        "Томаты вяленые 0,43кг": {"unit": "кг", "code": 3931},
        "Томаты консервированные": {"unit": "шт.", "code": 4809},
        "Укроп св": {"unit": "шт.", "code": 3984},
        "Цукини": {"unit": "шт.", "code": 3985},
        "Цукини маринованный п/ф": {"unit": "шт.", "code": 4549},
        "Чеснок св": {"unit": "шт.", "code": 3986},
        "Чеснок сух молотый": {"unit": "л", "code": 3874},
        "Шампиньоны св": {"unit": "шт.", "code": 4323},
        "Шпинат салат 0,125кг": {"unit": "кг", "code": 4341},
    },
    "Орехи": {
        "Арахис весовой кг": {"unit": "кг", "code": 3846},
        "Арахис жар солёный 50g": {"unit": "л", "code": 3845},
        "Кешью весовой кг": {"unit": "кг", "code": 3847},
        "Кешью жар 40g": {"unit": "шт.", "code": 3848},
        "Миндаль жар 40g": {"unit": "л", "code": 3850},
        "Смесь сл жар орехов с цукатами": {"unit": "л", "code": 3851},
        "Фисташки жар сол 40g": {"unit": "л", "code": 3852},
        "Фисташки жар кг": {"unit": "кг", "code": 3849},
        "Фундук суш 40g": {"unit": "шт.", "code": 3853},
    },
    "Прочее": {
        "Баклажан копченый п/ф": {"unit": "л", "code": 5465},
        "Брусника на пиве п/ф": {"unit": "шт.", "code": 3875},
        "Бульон куриный сухой": {"unit": "л", "code": 3829},
        "Горох": {"unit": "шт.", "code": 4406},
        "Горчица диж (ср-острая)": {"unit": "шт.", "code": 3876},
        "Горчица зернистая кг": {"unit": "кг", "code": 3877},
        "Йогурт Греческий": {"unit": "гр.", "code": 4864},
        "Крахмал": {"unit": "л", "code": 4870},
        "Лим кислота": {"unit": "л", "code": 4918},
        "Мука пшеничная": {"unit": "шт.", "code": 3960},
        "Свекла": {"unit": "л", "code": 4763},
        "Сухари панировочные": {"unit": "шт.", "code": 4387},
        "Томат паста": {"unit": "шт.", "code": 3967},
        "Уксус 9%": {"unit": "шт.", "code": 3832},
        "Уксус бальзамический": {"unit": "л", "code": 5590},
        "Фасоль консервированная": {"unit": "л", "code": 4838},
        "Щёки говяжьи": {"unit": "шт.", "code": 4475},
        "Ягоды можжевельника": {"unit": "л", "code": 3948},
    },
    "Рыба": {
        "Креветки 21/25 б/г с/м кг": {"unit": "кг", "code": 3924},
        "Рыба крабовые палочки": {"unit": "л", "code": 4240},
        "Сельдерей стебель св": {"unit": "л", "code": 3983},
        "Филе сельди с/с": {"unit": "л", "code": 4410},
    },
    "Сладости": {
        "Жев резинка в асс": {"unit": "шт.", "code": 3893},
        "Киндер": {"unit": "шт.", "code": 4556},
        "Крендель в асс": {"unit": "л", "code": 4316},
        "Мармелад в асс": {"unit": "л", "code": 4557},
        "Мороженое в ассортименте кг": {"unit": "кг", "code": 4343},
        "Печенье ОРЕО": {"unit": "шт.", "code": 4558},
        "Тик-так в асс": {"unit": "шт.", "code": 4806},
        "Холс в асс": {"unit": "л", "code": 4807},
        "Чупа-чупс": {"unit": "шт.", "code": 4563},
        "Энергетические конфеты": {"unit": "шт.", "code": 4289},
        "Энергетический батончик": {"unit": "шт.", "code": 4288},
    },
    "Соусы": {
        "Кетчуп": {"unit": "шт.", "code": 3878},
        "Крем из шамп с трюфелем": {"unit": "л", "code": 3879},
        "Мексиканская смесь": {"unit": "шт.", "code": 4875},
        "Соус Ворчестер 0,290кг": {"unit": "кг", "code": 3883},
        "Соус Гуакамоле": {"unit": "л", "code": 4863},
        "Соус Кимчи 1,8л": {"unit": "л", "code": 3887},
        "Соус барбекю": {"unit": "шт.", "code": 3881},
        "Соус вишневое варенье п/ф": {"unit": "шт.", "code": 3882},
        "Соус глазурь п/ф": {"unit": "л", "code": 3884},
        "Соус домашний кетчуп п/ф": {"unit": "шт.", "code": 3885},
        "Соус жидкий Чеддер": {"unit": "шт.", "code": 3886},
        "Соус жидкий дым": {"unit": "шт.", "code": 4223},
        "Соус кисло-сладкий": {"unit": "л", "code": 4582},
        "Соус крем бальзамик 0,6кг": {"unit": "кг", "code": 3888},
        "Соус ореховый": {"unit": "шт.", "code": 3889},
        "Соус перечный покупной": {"unit": "шт.", "code": 4098},
        "Соус соевый": {"unit": "шт.", "code": 3880},
        "Соус табаско 150мл": {"unit": "мл", "code": 5579},
        "Соус чили сладкий 0,92кг": {"unit": "кг", "code": 3890},
        "Соус чили-гарлик 0,24кг": {"unit": "кг", "code": 3891},
        "Соус шрирача": {"unit": "шт.", "code": 5409},
    },
    "Специи/Приправы": {
        "Кориандр молотый": {"unit": "л", "code": 3856},
        "Корица молотая": {"unit": "л", "code": 3857},
        "Кунжут черный": {"unit": "шт.", "code": 3858},
        "Куркума": {"unit": "шт.", "code": 3859},
        "Лавровый лист 20g": {"unit": "л", "code": 3860},
        "Мёд": {"unit": "шт.", "code": 3831},
        "Приправа 5 перцев горошек": {"unit": "шт.", "code": 3864},
        "Пять перцев дробленная 500g": {"unit": "л", "code": 3865},
        "Сахар Мусковадо тростниковый": {"unit": "шт.", "code": 3867},
        "Сахар порционный в стиках 5g": {"unit": "шт.", "code": 3866},
        "Сахарная пудра": {"unit": "шт.", "code": 3868},
        "Сахарозаменитель": {"unit": "л", "code": 3870},
        "Соль": {"unit": "л", "code": 3871},
        "Соль морская": {"unit": "л", "code": 3872},
        "Соль порционная 1g": {"unit": "л", "code": 3873},
    },
    "Фрукты": {
        "Ананас Сухофрукт": {"unit": "шт.", "code": 4485},
        "Апельсин св кг": {"unit": "кг", "code": 3945},
        "Брусника см": {"unit": "шт.", "code": 4246},
        "Вишня см": {"unit": "шт.", "code": 4247},
        "Лайм св": {"unit": "л", "code": 3946},
        "Лимоны св": {"unit": "л", "code": 3947},
        "Манго Сухофрукт": {"unit": "шт.", "code": 4484},
        "Облепиха см": {"unit": "л", "code": 4248},
    },
    "Хлеб": {
        "Багет пшеничный 0,3кг": {"unit": "кг", "code": 3949},
        "Бельгийская вафля 26шт": {"unit": "л", "code": 3892},
        "Берлинер-Донатс": {"unit": "л", "code": 4244},
        "Брецель-дог (сосиска в тесте)": {"unit": "л", "code": 4278},
        "Булочка белая для бургера": {"unit": "л", "code": 3952},
        "Булочка зерновая": {"unit": "л", "code": 3950},
        "Булочка картофельная": {"unit": "л", "code": 3951},
        "Булочка черная для бургера": {"unit": "л", "code": 3953},
        "Донатс в асс": {"unit": "шт.", "code": 4245},
        "Лаваш 30см": {"unit": "л", "code": 4836},
        "Хлеб белый/чёрный": {"unit": "л", "code": 3969},
        "Хлеб бородинский 0,7кг": {"unit": "кг", "code": 3954},
    },
    "Чипсы/Снеки": {
        "Вяленое мясо снек Гурмэ микс 150g": {"unit": "л", "code": 4138},
        "Вяленое мясо снек в асс 50g": {"unit": "л", "code": 4137},
        "Сухарики фишка": {"unit": "шт.", "code": 4228},
        "Чака снек микс 50g": {"unit": "шт.", "code": 4229},
        "Чипсы Лей*с в асс": {"unit": "л", "code": 3854},
        "Чипсы Принглс в асс": {"unit": "л", "code": 4564},
        "Чипсы Хантерс в асс 0,025гр": {"unit": "гр.", "code": 5517},
        "Чипсы Хантерс в асс 0,125гр": {"unit": "гр.", "code": 5518},
        "Чипсы Хантерс в асс 0,150гр": {"unit": "гр.", "code": 5519},
    },
    "Яйца": {
        "Меланж": {"unit": "л", "code": 5401},
        "Яйцо куриное шт": {"unit": "шт.", "code": 3834},
    },
}

LOCATIONS = {
    "Склад": {},
    "Кухня": {},
    "Островок": {}
}

def init_locations():
    for location in LOCATIONS:
        for category, products in GLOBAL_PRODUCTS.items():
            LOCATIONS[location][category] = dict(products)

init_locations()

# ============== АВТОРИЗАЦИЯ ==============
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with users_lock:
            if username in users and check_password_hash(users[username]['password'], password):
                session['username'] = username
                session['role'] = users[username]['role']
                return redirect('/admin' if users[username]['role'] == 'admin' else '/revision')
            else:
                return render_template_string(login_html, error="❌ Неверный логин или пароль")
    return render_template_string(login_html, now=datetime.now().strftime("%d.%m %H:%M"))

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

login_html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Вход</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap" rel="stylesheet">
<style>
:root {
    --primary: #6366f1;
    --primary-dark: #4f46e5;
    --bg-gradient: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    --card-bg: rgba(255, 255, 255, 0.95);
    --text-color: #1e293b;
    --error-bg: #fee2e2;
    --error-text: #991b1b;
}
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
body {
    font-family: 'Outfit', sans-serif;
    background: var(--bg-gradient);
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0;
    padding: 20px;
}
.login-box {
    background: var(--card-bg);
    padding: 40px 30px;
    border-radius: 24px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    max-width: 400px;
    width: 100%;
    backdrop-filter: blur(10px);
    animation: fadeIn 0.5s ease-out;
}
@keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
h1 {
    text-align: center;
    color: var(--primary);
    margin-bottom: 30px;
    font-weight: 600;
    font-size: 28px;
}
.form-group { margin-bottom: 20px; }
.form-group label {
    display: block;
    margin-bottom: 8px;
    font-weight: 600;
    color: #475569;
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.form-group input {
    width: 100%;
    padding: 14px 16px;
    border: 2px solid #e2e8f0;
    border-radius: 12px;
    font-size: 16px;
    transition: all 0.3s ease;
    background: #f8fafc;
}
.form-group input:focus {
    outline: none;
    border-color: var(--primary);
    background: white;
    box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.1);
}
.btn {
    width: 100%;
    background: var(--primary);
    color: white;
    border: none;
    padding: 16px;
    border-radius: 12px;
    font-weight: 600;
    cursor: pointer;
    font-size: 16px;
    transition: transform 0.2s, box-shadow 0.2s;
    margin-top: 10px;
}
.btn:active { transform: scale(0.98); }
.error {
    color: var(--error-text);
    background: var(--error-bg);
    padding: 12px;
    border-radius: 12px;
    margin-bottom: 20px;
    text-align: center;
    font-size: 14px;
    border: 1px solid #fecaca;
}
</style>
</head>
<body>
<div class="login-box">
<h1>🔐 Вход</h1>
{% if error %}<div class="error">{{error}}</div>{% endif %}
<form method="post">
<div class="form-group">
  <label>Логин</label>
  <input type="text" name="username" required autocomplete="username">
</div>
<div class="form-group">
  <label>Пароль</label>
  <input type="password" name="password" required autocomplete="current-password">
</div>
<button class="btn" type="submit">Войти</button>
</form>
<div style="text-align:center;color:#999;font-size:12px;margin-top:20px;">Версия: {{ now }}</div>
</div>
</body>
</html>'''

# ============== ПРОВЕРКА АВТОРИЗАЦИИ ==============
def require_login(f):
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def require_admin(f):
    def wrapper(*args, **kwargs):
        if 'username' not in session or session.get('role') != 'admin':
            return redirect('/login')
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

# ============== АДМИН ПАНЕЛЬ ==============
@app.route('/admin')
@require_admin
def admin_panel():
    with users_lock:
        user_list = [(u, users[u]['role']) for u in users]
    html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Панель Администратора</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap" rel="stylesheet">
<style>
:root {
    --primary: #6366f1;
    --primary-dark: #4f46e5;
    --bg-body: #f8fafc;
    --card-bg: #ffffff;
    --text-main: #0f172a;
    --text-muted: #64748b;
    --danger: #ef4444;
}
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
body {
    font-family: 'Outfit', sans-serif;
    background: var(--bg-body);
    margin: 0;
    padding: 0;
    color: var(--text-main);
    padding-bottom: 40px;
}
header {
    background: var(--card-bg);
    padding: 20px;
    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
    margin-bottom: 20px;
}
header h1 { margin: 0; font-size: 22px; color: var(--primary); }
.header-actions { display: flex; gap: 10px; margin-top: 15px; }
.btn {
    padding: 10px 16px;
    border: none;
    border-radius: 10px;
    font-weight: 500;
    cursor: pointer;
    font-size: 14px;
    transition: all 0.2s;
}
.btn-primary { background: var(--primary); color: white; }
.btn-danger { background: #fee2e2; color: var(--danger); }
.btn-outline { background: white; border: 1px solid #e2e8f0; color: var(--text-main); }
.tabs {
    display: flex;
    overflow-x: auto;
    padding: 0 20px 20px;
    gap: 10px;
    scrollbar-width: none;
}
.tab-btn {
    padding: 10px 20px;
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 50px;
    white-space: nowrap;
    color: var(--text-muted);
    font-weight: 500;
}
.tab-btn.active {
    background: var(--primary);
    color: white;
    border-color: var(--primary);
    box-shadow: 0 4px 12px rgba(99, 102, 241, 0.2);
}
.tab-content { display: none; padding: 0 20px; }
.tab-content.active { display: block; animation: fadeIn 0.3s; }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

.card {
    background: var(--card-bg);
    padding: 24px;
    border-radius: 20px;
    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
    margin-bottom: 20px;
}
.card h2 { margin-top: 0; font-size: 18px; color: var(--text-main); margin-bottom: 20px; }
.form-input {
    width: 100%;
    padding: 12px;
    border: 2px solid #e2e8f0;
    border-radius: 12px;
    margin-bottom: 15px;
    font-family: inherit;
}
.user-list { width: 100%; border-collapse: collapse; }
.user-list td { padding: 12px 0; border-bottom: 1px solid #f1f5f9; }

/* Product Delete UI */
.search-results {
    max-height: 200px;
    overflow-y: auto;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    margin-bottom: 15px;
    display: none;
}
.search-item { padding: 10px; cursor: pointer; border-bottom: 1px solid #f1f5f9; }
.search-item:hover { background: #f8fafc; }
.scope-selector { display: flex; flex-direction: column; gap: 10px; margin: 15px 0; display: none; }
.scope-option {
    padding: 12px;
    border: 2px solid #e2e8f0;
    border-radius: 10px;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 10px;
}
.scope-option.selected { border-color: var(--danger); background: #fef2f2; }
</style>
</head>
<body>
<header>
    <h1>👨‍💼 Панель Администратора</h1>
    <div class="header-actions">
        <a href="/revision"><button class="btn btn-primary">📊 Ревизия</button></a>
        <a href="/logout"><button class="btn btn-outline">Выход</button></a>
    </div>
</header>

<div class="tabs">
    <button class="tab-btn active" onclick="switchTab('users')">Пользователи</button>
    <button class="tab-btn" onclick="switchTab('products')">Товары</button>
    <button class="tab-btn" onclick="switchTab('requests')">Запросы</button>
</div>

<div id="users" class="tab-content active">
    <!-- User Management -->
    <div class="card">
        <h2>Создать оператора</h2>
        <form method="post" action="/admin/create_user">
            <input class="form-input" type="text" name="username" placeholder="Логин" required>
            <input class="form-input" type="text" name="password" placeholder="Пароль (опционально)">
            <button class="btn btn-primary" type="submit">Создать</button>
        </form>
    </div>
    <div class="card">
        <h2>Активные пользователи</h2>
        <table class="user-list">
        {% for user, role in users %}
        <tr>
            <td><strong>{{user}}</strong> <span style="color:var(--text-muted);font-size:12px;">{{role}}</span></td>
            <td align="right">
            {% if user != 'admin' %}
            <form method="post" action="/admin/delete_user" style="display:inline;">
            <input type="hidden" name="username" value="{{user}}">
            <button class="btn btn-danger" onclick="return confirm('Удалить?')">×</button>
            </form>
            {% endif %}
            </td>
        </tr>
        {% endfor %}
        </table>
    </div>
</div>

<div id="products" class="tab-content">
    
    <!-- Smart Delete -->
    <div class="card" style="border: 2px solid #fee2e2;">
        <h2 style="color:var(--danger)">🗑 Выборочное удаление</h2>
        <input type="text" id="pSearch" class="form-input" placeholder="Начните вводить название..." onkeyup="searchProd()">
        <div id="searchResults" class="search-results"></div>
        
        <div id="deleteScope" class="scope-selector">
            <h3 style="font-size:14px;margin:0;">Где удалить <b id="selectedProd"></b>?</h3>
            <div class="scope-option" onclick="toggleScope('global', this)" id="opt-global">
                <span>🌍 Везде (Глобально)</span>
            </div>
            <div style="font-size:12px;color:#999;margin-left:5px;">ИЛИ Выберите конкретно:</div>
            {% for loc in LOCATIONS %}
            <div class="scope-option location-opt" onclick="toggleScope('{{loc}}', this)">
                <span>📍 {{loc}}</span>
            </div>
            {% endfor %}
            <button class="btn btn-danger" style="margin-top:10px;" onclick="confirmDelete()">Подтвердить удаление</button>
        </div>
    </div>

    <!-- Standard Edit -->
    <div class="card">
        <h2>Добавить / Удалить (Стандарт)</h2>
        <form method="post" action="/admin/edit_products">
            <div style="margin-bottom:15px; border: 1px solid #e2e8f0; padding: 10px; border-radius: 12px;">
                <label style="display:block; margin-bottom:10px; font-weight:600;">Где добавить/изменить?</label>
                <div style="display:flex; flex-direction:column; gap:8px;">
                     <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                        <input type="checkbox" id="addAllGlobal" onchange="toggleAllAdd(this)">
                        <strong>🌍 Везде (Глобально)</strong>
                    </label>
                    <div style="height:1px; background:#e2e8f0; margin:5px 0;"></div>
                    {% for loc in LOCATIONS %}
                    <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                        <input type="checkbox" name="locations" value="{{loc}}" class="add-loc-check">
                        <span>📍 {{loc}}</span>
                    </label>
                    {% endfor %}
                </div>
            </div>
            
            <input class="form-input" type="text" name="category" placeholder="Категория" required>
            <input class="form-input" type="text" name="name" placeholder="Название" required>
            <input class="form-input" type="text" name="code" placeholder="Код (Штрих-код)">
            <input class="form-input" type="text" name="unit" placeholder="Ед. изм. (напр. шт)">
            <button class="btn btn-primary" type="submit" name="action" value="add">Добавить / Обновить</button>
            <button class="btn btn-danger" type="submit" name="action" value="remove">Удалить</button>
        </form>
        <script>
        function toggleAllAdd(source) {
            document.querySelectorAll('.add-loc-check').forEach(c => {
                c.checked = source.checked;
            });
        }
        </script>
    </div>
</div>

<div id="requests" class="tab-content">
    <div class="card">
        <h2>Запросы на завершение</h2>
        {% if not pending_finish %}
        <p style="color:#999;text-align:center;">Нет ожидающих запросов</p>
        {% else %}
        {% for req_id, data in pending_finish.items() %}
        <div style="background:#f8fafc;padding:15px;border-radius:12px;margin-bottom:10px;">
            <div><strong>{{data.location}}</strong> <small>{{data.timestamp}}</small></div>
            <div style="color:#666;margin:5px 0;">от {{data.user}}</div>
            <div style="display:flex;gap:10px;margin-top:10px;">
                <form method="post" action="/admin/finish_confirm" style="width:100%">
                    <input type="hidden" name="request_id" value="{{req_id}}">
                    <button class="btn btn-primary" style="width:100%">Подтвердить</button>
                </form>
                 <form method="post" action="/admin/finish_cancel" style="width:100%">
                    <input type="hidden" name="request_id" value="{{req_id}}">
                    <button class="btn btn-danger" style="width:100%">Отклонить</button>
                </form>
            </div>
        </div>
        {% endfor %}
        {% endif %}
    </div>
</div>

<script>
function switchTab(t) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    document.getElementById(t).classList.add('active');
    event.target.classList.add('active');
}

/* Delete Logic */
let selectedProduct = null;
let deleteScope = [];

async function searchProd() {
    const q = document.getElementById('pSearch').value;
    if(q.length < 2) { document.getElementById('searchResults').style.display='none'; return; }
    
    const res = await fetch('/admin/search_products?q='+encodeURIComponent(q));
    const list = await res.json();
    
    const div = document.getElementById('searchResults');
    div.innerHTML = '';
    div.style.display = list.length ? 'block' : 'none';
    
    list.forEach(p => {
        const el = document.createElement('div');
        el.className = 'search-item';
        el.innerText = p;
        el.onclick = () => selectForDelete(p);
        div.appendChild(el);
    });
}

function selectForDelete(name) {
    selectedProduct = name;
    document.getElementById('pSearch').value = name;
    document.getElementById('searchResults').style.display = 'none';
    document.getElementById('selectedProd').innerText = name;
    document.getElementById('deleteScope').style.display = 'flex';
    deleteScope = [];
    document.querySelectorAll('.scope-option').forEach(el => el.classList.remove('selected'));
}

function toggleScope(val, el) {
    if (val === 'global') {
        const isSel = deleteScope === 'global';
        if (!isSel) {
            deleteScope = 'global';
            document.querySelectorAll('.scope-option').forEach(e => e.classList.remove('selected'));
            el.classList.add('selected');
        } else {
            deleteScope = [];
            el.classList.remove('selected');
        }
    } else {
        if (deleteScope === 'global') {
            deleteScope = [];
            document.getElementById('opt-global').classList.remove('selected');
        }
        const idx = deleteScope.indexOf(val);
        if (idx > -1) {
            deleteScope.splice(idx, 1);
            el.classList.remove('selected');
        } else {
            deleteScope.push(val);
            el.classList.add('selected');
        }
    }
}

async function confirmDelete() {
    if (!selectedProduct || (!deleteScope.length && deleteScope !== 'global')) {
         alert('Пожалуйста, выберите товар и место удаления.');
         return;
    }
    if (!confirm('Вы уверены, что хотите удалить ' + selectedProduct + '?')) return;
    
    await fetch('/admin/delete_product', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({product: selectedProduct, scope: deleteScope})
    });
    
    alert('Удалено!');
    window.location.reload();
}
</script>
</body>
</html>''' 
    return render_template_string(html, users=user_list, pending_finish=pending_finish, LOCATIONS=LOCATIONS)

@app.route('/admin/create_user', methods=['POST'])
@require_admin
def create_user():
    username = request.form['username']
    password = request.form['password'] or secrets.token_urlsafe(8)
    with users_lock:
        if username not in users:
            users[username] = {'password': generate_password_hash(password), 'role': 'operator'}
    return redirect('/admin')

@app.route('/admin/delete_user', methods=['POST'])
@require_admin
def delete_user():
    username = request.form['username']
    with users_lock:
        if username in users and username != 'admin':
            del users[username]
    return redirect('/admin')

@app.route('/admin/edit_products', methods=['POST'])
@require_admin
def edit_products():
    locations = request.form.getlist('locations')
    category = request.form['category']
    name = request.form['name']
    code = request.form['code']
    unit = request.form['unit']
    action = request.form['action']
    
    # Если ничего не выбрано, ничего не делаем (или можно добавить default)
    if not locations:
        return redirect('/admin')

    for location in locations:
        # Защита если вдруг локация кривая
        if location not in LOCATIONS:
            continue
            
        if action == 'add':
            if category not in LOCATIONS[location]:
                LOCATIONS[location][category] = {}
            LOCATIONS[location][category][name] = {'code': code, 'unit': unit}
        elif action == 'remove':
            if category in LOCATIONS[location] and name in LOCATIONS[location][category]:
                del LOCATIONS[location][category][name]
                # Удаляем категорию если пустая
                if not LOCATIONS[location][category]:
                    del LOCATIONS[location][category]
                    
    return redirect('/admin')

@app.route('/admin/search_products')
@require_admin
def search_products():
    query = request.args.get('q', '').lower()
    results = set()
    for loc_data in LOCATIONS.values():
        for cat, products in loc_data.items():
            for name in products:
                if query in name.lower():
                    results.add(name)
    return jsonify(list(results))

@app.route('/admin/delete_product', methods=['POST'])
@require_admin
def delete_product_endpoint():
    data = request.json
    product_name = data.get('product')
    scope = data.get('scope') # 'global' or list of locations
    
    if scope == 'global':
        # Remove from GLOBAL_PRODUCTS
        for cat in list(GLOBAL_PRODUCTS.keys()):
            if product_name in GLOBAL_PRODUCTS[cat]:
                del GLOBAL_PRODUCTS[cat][product_name]
        # Remove from all locations
        for loc in LOCATIONS:
            for cat in list(LOCATIONS[loc].keys()):
                if product_name in LOCATIONS[loc][cat]:
                    del LOCATIONS[loc][cat][product_name]
    else:
        # Remove from specific locations
        for loc in scope:
            if loc in LOCATIONS:
                for cat in list(LOCATIONS[loc].keys()):
                    if product_name in LOCATIONS[loc][cat]:
                        del LOCATIONS[loc][cat][product_name]
                        
    return jsonify({'status': 'ok'})

@app.route("/admin/finish_confirm", methods=["POST"])
@require_admin
def finishconfirm():
    requestid = request.form.get("request_id")
    if requestid in pending_finish:
        data = pending_finish[requestid]
        operator_name = data.get('user', 'Unknown')
        timestamp = data.get('timestamp', '')

        # создаём новую книгу Excel
        wb = Workbook()
        ws = wb.active
        ws.title = "Revision"

        # Добавляем информацию о ревизии
        ws.append(["Ревизия от:", timestamp])
        ws.append(["Оператор:", operator_name])
        ws.append([]) # Пустая строка

        # шапка таблицы (убрали Локацию, оставили Итог)
        ws.append(["Категория", "Товар", "Штрих‑код", "Ед.", "Общее Количество"])

        # Сбор данных и агрегация
        aggregated_data = {} # (category, name) -> {code, unit, total_qty}

        with inventory_lock:
            # 1. Проходим по всем локациям и товарам в них
            for location in LOCATIONS:
                for cat, products in LOCATIONS[location].items():
                    for name, info in products.items():
                        key = (cat, name)
                        if key not in aggregated_data:
                            aggregated_data[key] = {
                                "code": info.get("code", ""),
                                "unit": info.get("unit", ""),
                                "qty": 0
                            }
                        
                        # Добавляем количество из инвентаря текущей локации
                        qty = inventory.get((location, name), 0)
                        aggregated_data[key]["qty"] += qty

        # 2. Записываем агрегированные данные в Excel
        # Сортируем по категории, затем по имени
        sorted_keys = sorted(aggregated_data.keys())
        
        for cat, name in sorted_keys:
            data = aggregated_data[(cat, name)]
            ws.append([
                cat,
                name,
                data["code"],
                data["unit"],
                data["qty"]
            ])

        # сохраняем в память
        output = io.BytesIO()
        wb.save(output)
        output.seek(0)

        # очищаем состояние ревизии
        inventory.clear()
        history.clear()
        del pending_finish[requestid]

        # отправляем файл пользователю
        filename = f"revision_{timestamp.replace(':', '-')}_{operator_name}.xlsx"
        return send_file(
            output,
            as_attachment=True,
            download_name=filename,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

    return redirect("/admin")

@app.route('/admin/finish_cancel', methods=['POST'])
@require_admin
def finish_cancel():
    request_id = request.form['request_id']
    if request_id in pending_finish:
        del pending_finish[request_id]
    return redirect('/admin')

# ============== РЕВИЗИЯ (Для операторов и админа) ==============
@app.route('/revision')
@require_login
def revision():
    selected_location = request.args.get("location", "Склад")
    with inventory_lock:
        inv = dict(inventory)
    
    return render_template_string(revision_html, locations=LOCATIONS, inventory=inv, current=selected_location, role=session.get('role', 'operator'))

revision_html = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Ревизия</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap" rel="stylesheet">
<style>
:root {
    --primary: #6366f1;
    --primary-light: #818cf8;
    --bg-body: #f1f5f9;
    --card-bg: #ffffff;
    --text-main: #1e293b;
    --text-muted: #64748b;
    --success: #10b981;
    --danger: #ef4444;
}
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
body {
    font-family: 'Outfit', sans-serif;
    background: var(--bg-body);
    margin: 0;
    padding: 0;
    color: var(--text-main);
    padding-bottom: 80px; /* Space for bottom actions */
}
header {
    background: var(--card-bg);
    padding: 15px 20px;
    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
    position: sticky;
    top: 0;
    z-index: 100;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
header h1 {
    margin: 0;
    font-size: 20px;
    font-weight: 700;
    background: linear-gradient(135deg, var(--primary), var(--primary-light));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.header-actions { display: flex; gap: 10px; }
.btn-icon {
    background: #f8fafc;
    border: none;
    padding: 8px 12px;
    border-radius: 8px;
    color: var(--text-main);
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
}
.tabs {
    display: flex;
    overflow-x: auto;
    padding: 15px 20px;
    gap: 12px;
    background: var(--bg-body);
    scrollbar-width: none;
}
.tabs::-webkit-scrollbar { display: none; }
.tab {
    padding: 8px 20px;
    background: white;
    border-radius: 50px;
    font-weight: 600;
    color: var(--text-muted);
    text-decoration: none;
    white-space: nowrap;
    box-shadow: 0 1px 2px rgba(0,0,0,0.05);
    transition: all 0.2s;
    font-size: 14px;
}
.tab.active {
    background: var(--primary);
    color: white;
    box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
}
.container { padding: 0 20px; }
.search-box {
    position: sticky;
    top: 60px;
    z-index: 90;
    background: var(--bg-body);
    padding: 10px 0;
}
.search-box input {
    width: 100%;
    padding: 12px 16px;
    border: none;
    border-radius: 12px;
    background: white;
    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
    font-size: 16px;
    font-family: inherit;
}
.product-group { margin-bottom: 25px; }
.product-group h3 {
    margin: 15px 0 10px;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
    font-weight: 700;
}
.product-item {
    background: var(--card-bg);
    padding: 16px;
    border-radius: 12px;
    margin-bottom: 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    cursor: pointer;
    transition: transform 0.1s;
}
.product-item:active { transform: scale(0.98); }
.p-name { font-weight: 500; font-size: 15px; }
.p-meta { font-size: 12px; color: var(--text-muted); margin-top: 4px; }
.badge {
    background: var(--primary);
    color: white;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 14px;
    font-weight: 600;
    min-width: 30px;
    text-align: center;
}
/* Modal & Calc */
.modal {
    display: none;
    position: fixed;
    top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(4px);
    z-index: 1000;
    align-items: flex-end; /* Sheet style on mobile */
}
.modal.active { display: flex; animation: fadeIn 0.2s; }
.modal-content {
    background: white;
    width: 100%;
    border-radius: 24px 24px 0 0;
    padding: 24px;
    box-shadow: 0 -10px 40px rgba(0,0,0,0.2);
    animation: slideUp 0.3s cubic-bezier(0.16, 1, 0.3, 1);
}
@keyframes slideUp { from { transform: translateY(100%); } to { transform: translateY(0); } }
.calc-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.calc-title { font-size: 18px; font-weight: 700; color: var(--text-main); max-width: 80%; }
.calc-display {
    width: 100%;
    font-size: 32px;
    padding: 10px;
    text-align: right;
    border: none;
    border-bottom: 2px solid #e2e8f0;
    margin-bottom: 20px;
    font-family: 'Outfit', monospace;
    color: var(--primary);
    background: transparent;
}
.calc-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
.c-btn {
    padding: 15px;
    border-radius: 12px;
    border: none;
    font-size: 20px;
    font-weight: 500;
    background: #f1f5f9;
    color: var(--text-main);
    touch-action: manipulation;
}
.c-btn:active { background: #e2e8f0; }
.op-btn { background: #e0e7ff; color: var(--primary); }
.submit-btn {
    grid-column: span 2;
    background: var(--primary);
    color: white;
    font-weight: 600;
}
.total-row {
    margin-top: 15px;
    text-align: center;
    font-size: 16px;
    color: var(--text-muted);
}
.highlight { color: var(--primary); font-weight: 700; }

.finish-btn {
    position: fixed;
    bottom: 20px;
    left: 20px;
    right: 20px;
    background: var(--text-main);
    color: white;
    border: none;
    padding: 16px;
    border-radius: 16px;
    font-size: 16px;
    font-weight: 600;
    box-shadow: 0 10px 20px rgba(0,0,0,0.1);
    z-index: 90;
}
</style>
</head>
<body>
<header>
    <h1>Инвентаризация</h1>
    <div class="header-actions">
        {% if role == 'admin' %}
        <a href="/admin"><button class="btn-icon">⚙️ Админ</button></a>
        {% endif %}
        <a href="/logout"><button class="btn-icon">Выход</button></a>
    </div>
</header>

<div class="tabs">
    <a href="/revision?location=Склад" class="tab {% if 'Склад' == current %}active{% endif %}">Склад</a>
    <a href="/revision?location=Кухня" class="tab {% if 'Кухня' == current %}active{% endif %}">Кухня</a>
    <a href="/revision?location=Островок" class="tab {% if 'Островок' == current %}active{% endif %}">Островок</a>
</div>

<div class="container">
    <div class="search-box">
        <input type="text" id="search" placeholder="🔍 Поиск товара..." onkeyup="filterProducts()">
    </div>

    <div id="productList">
    {% for cat, products in locations[current].items() %}
      <div class="product-group">
      <h3>{{cat}}</h3>
      {% for name, data in products.items() %}
      {% set qty = inventory.get((current, name), 0) %}
      <div class="product-item" data-name="{{name | lower}}" onclick="openCalc('{{current}}','{{name}}','{{data.unit}}')">
        <div>
            <div class="p-name">{{name}}</div>
            <div class="p-meta">{{data.unit}}</div>
        </div>
        {% if qty > 0%}<div class="badge">{{qty}}</div>{% endif %}
      </div>
      {% endfor %}
      </div>
    {% endfor %}
    </div>
</div>

<button class="finish-btn" onclick="requestFinish()">Завершить ревизию</button>

<!-- Calculator Modal -->
<div class="modal" id="calcModal" onclick="if(event.target===this)closeCalc()">
<div class="modal-content">
    <div class="calc-header">
        <div class="calc-title" id="calcTitle"></div>
        <button class="btn-icon" onclick="closeCalc()">✕</button>
    </div>
    <input type="text" id="calcDisplay" class="calc-display" readonly value="0">
    <div class="calc-grid">
        <button class="c-btn" onclick="num('7')">7</button>
        <button class="c-btn" onclick="num('8')">8</button>
        <button class="c-btn" onclick="num('9')">9</button>
        <button class="c-btn op-btn" onclick="setOp('/')">÷</button>
        
        <button class="c-btn" onclick="num('4')">4</button>
        <button class="c-btn" onclick="num('5')">5</button>
        <button class="c-btn" onclick="num('6')">6</button>
        <button class="c-btn op-btn" onclick="setOp('*')">×</button>
        
        <button class="c-btn" onclick="num('1')">1</button>
        <button class="c-btn" onclick="num('2')">2</button>
        <button class="c-btn" onclick="num('3')">3</button>
        <button class="c-btn op-btn" onclick="setOp('-')">−</button>
        
        <button class="c-btn" onclick="num('.')">.</button>
        <button class="c-btn" onclick="num('0')">0</button>
        <button class="c-btn" onclick="clr()">C</button>
        <button class="c-btn op-btn" onclick="setOp('+')">+</button>
        
        <button class="c-btn op-btn" onclick="calculate()">=</button>
        <button class="c-btn op-btn" onclick="addToTotal()">+</button>
        <button class="c-btn submit-btn" onclick="saveResult()">СОХРАНИТЬ</button>
    </div>
    <div class="total-row">Итого: <span id="total" class="highlight">0</span> <span id="unit"></span></div>
</div>
</div>

<!-- Confirm Modal -->
<div class="modal" id="confirmModal">
<div class="modal-content" style="text-align:center;border-radius:24px;">
    <h2 style="color:var(--primary);">Запрос отправлен</h2>
    <p style="color:var(--text-muted);margin-bottom:20px;">Ожидание подтверждения администратором...</p>
    <button class="finish-btn" style="position:static;background:#cbd5e1;color:#333;" onclick="cancelRequest()">Отмена</button>
</div>
</div>

<script>
let loc='', prod='', unit='';
let val='0', op=null, prev=null, total=0;

function filterProducts(){
  const filter=document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('.product-item').forEach(item=>{
    item.style.display=item.getAttribute('data-name').includes(filter)?'flex':'none';
    if(item.style.display==='flex') item.closest('.product-group').style.display='block';
  });
  // Hide empty groups
  document.querySelectorAll('.product-group').forEach(group => {
     const visibleItems = Array.from(group.querySelectorAll('.product-item')).filter(i => i.style.display !== 'none');
     group.style.display = visibleItems.length > 0 ? 'block' : 'none';
  });
}

function openCalc(l,p,u){
  loc=l;prod=p;unit=u;total=0;val='0';op=null;prev=null;
  document.getElementById('calcTitle').innerText=p;
  document.getElementById('unit').innerText=u;
  document.getElementById('calcDisplay').value='0';
  document.getElementById('total').innerText='0';
  document.getElementById('calcModal').classList.add('active');
}

function closeCalc(){document.getElementById('calcModal').classList.remove('active');}

function num(n){if(val==='0'||val==='Error')val=n;else val+=n;document.getElementById('calcDisplay').value=val;}
function setOp(o){prev=parseFloat(val);val='0';op=o;}
function calculate(){if(op&&prev!=null){const cur=parseFloat(val);let r;
  switch(op){case '+':r=prev+cur;break;case '-':r=prev-cur;break;case '*':r=prev*cur;break;case '/':r=cur!==0?prev/cur:'Error';break;}
  val=r.toString();op=null;prev=null;document.getElementById('calcDisplay').value=val;}}
function clr(){val='0';prev=null;op=null;document.getElementById('calcDisplay').value='0';}
function addToTotal(){calculate();let n=parseFloat(val);if(!isNaN(n))total+=n;document.getElementById('total').innerText=total;val='0';document.getElementById('calcDisplay').value='0';}

async function saveResult(){
  let n=total>0?total:parseFloat(val);
  if(isNaN(n)||n<=0){alert('Пожалуйста, введите корректное число');return;}
  const fd=new FormData();fd.append('location',loc);fd.append('name',prod);fd.append('count',n);
  await fetch('/add_api',{method:'POST',body:fd});
  closeCalc();window.location.reload();
}

async function requestFinish(){
  const resp = await fetch('/request_finish?location=' + encodeURIComponent(loc||'Все'), {method:'POST'});
  document.getElementById('confirmModal').classList.add('active');
}

function cancelRequest(){
  document.getElementById('confirmModal').classList.remove('active');
  // Logic to actually cancel on server could be added here
}
</script>
</body>
</html>'''

@app.route('/add_api', methods=['POST'])
@require_login
def add_api():
    location = request.form['location']
    name = request.form['name']
    count = float(request.form['count'])
    timestamp = datetime.now().strftime("%d.%m %H:%M:%S")
    key = (location, name)
    with inventory_lock:
        inventory[key] = inventory.get(key, 0) + count
        history.setdefault(key, []).append(f"{timestamp}: {session['username']} добавил {count}")
    return ('', 204)

@app.route('/request_finish', methods=['POST'])
@require_login
def request_finish():
    request_id = secrets.token_urlsafe(8)
    location = request.args.get('location', 'Все')
    pending_finish[request_id] = {
        'user': session['username'],
        'location': location,
        'timestamp': datetime.now().strftime("%d.%m %H:%M:%S")
    }
    return jsonify({'request_id': request_id})

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 7000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(host="0.0.0.0", port=port, debug=debug)
