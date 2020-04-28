## CyberSEC & anti-SPY



```bash
'╔═╗┌─┐┌─┐┬ ┬┬─┐┬┌┬┐┬ ┬
'╚═╗├┤ │ │ │├┬┘│ │ └┬┘
'╚═╝└─┘└─┘└─┘┴└─┴ ┴ ┴ 
Все о вопросах безопасности.
```



awesome-windows-kernel-security-development


#### [windows-kernel-security-development](https://github.com/ExpLife0011/awesome-windows-kernel-security-development)




[shadowsocksr](https://github.com/shadowsocksrr/shadowsocksr)


Подымаем свой VPN и обходим блокировку сайтов (по Китайской технологии обход_Золотого_щита)

[FAKE CMD](https://github.com/Ondrik8/-Security/blob/master/cmd.exe) для хакеров! ;p

[attack_monitor](https://hakin9.org/attack-monitor-endpoint-detection-and-malware-analysis-software/)  мониторинг атак.

[Real Time Threat Monitoring](https://github.com/NaveenRudra/RTTM)

[BLUESPAWN](https://github.com/ION28/BLUESPAWN)

# Demo
![demo/ed.gif](https://raw.githubusercontent.com/yarox24/attack_monitor/master/demo/ed.gif)


[BZAR](https://github.com/mitre-attack/bzar) инструмент для обнаружение вторжений на основе данных mitre-attack

[Destroy Windows 10 Spying](https://github.com/Wohlstand/Destroy-Windows-10-Spying/releases)   Destroy Windows 10 Spying он отключает кейлоггеры, тех отчеты и блокирует IP адреса дяди Била.)

 [windows_hardening](https://github.com/0x6d69636b/windows_hardening) Это контрольный список для усиления защиты, который можно использовать в частных и бизнес-средах для защиты Windows 10. Контрольный список можно использовать для всех версий Windows, но в Windows 10 Home редактор групповой политики не интегрирован, и настройку необходимо выполнить непосредственно в реестр.
Параметры следует рассматривать как рекомендацию по безопасности и конфиденциальности, и их следует тщательно проверять, не повлияет ли они на работу вашей инфраструктуры или на удобство использования ключевых функций. Важно взвесить безопасность против юзабилити.
 

[reverse-vulnerabilities-software](https://www.apriorit.com/dev-blog/644-reverse-vulnerabilities-software-no-code-dynamic-fuzzing) Как обнаружить уязвимости в программном обеспечении, когда исходный код недоступен.




### IDS / IPS / Host IDS / Host IPS

- [Snort](https://www.snort.org/) - Snort - это бесплатная система с открытым исходным кодом для предотвращения вторжений (NIPS) и система обнаружения вторжений в сеть (NIDS), созданная Мартином Рошем в 1998 году. Snort в настоящее время разрабатывается. Sourcefire, основателем которого является Роеш и технический директор. В 2009 году Snort вошел в Зал Славы InfoWorld с открытым исходным кодом как одно из «величайших [образцов] программного обеспечения с открытым исходным кодом всех времен».
- [Bro](https://www.bro.org/) - Bro - это мощная инфраструктура сетевого анализа, которая сильно отличается от типичной IDS, которую вы, возможно, знаете.
- [OSSEC](https://ossec.github.io/) - Комплексная HIDS с открытым исходным кодом. Не для слабонервных. Требуется немного, чтобы понять, как это работает. Выполняет анализ журналов, проверку целостности файлов, мониторинг политик, обнаружение руткитов, оповещение в режиме реального времени и активный ответ. Он работает в большинстве операционных систем, включая Linux, MacOS, Solaris, HP-UX, AIX и Windows. Много разумной документации. Сладкое место - от среднего до крупного развертывания.
- [Suricata](http://suricata-ids.org/) - Suricata - это высокопроизводительный механизм мониторинга сетевых IDS, IPS и сетевой безопасности. Open Source и принадлежит общественному некоммерческому фонду Open Foundation Security Foundation (OISF). Suricata разработана OISF и его поставщиками.
- [Security Onion](http://blog.securityonion.net/) - Security Onion - это дистрибутив Linux для обнаружения вторжений, мониторинга сетевой безопасности и управления журналами. Он основан на Ubuntu и содержит Snort, Suricata, Bro, OSSEC, Sguil, Squert, Snorby, ELSA, Xplico, NetworkMiner и многие другие инструменты безопасности. Простой в использовании мастер установки позволяет создать целую армию распределенных датчиков для вашего предприятия за считанные минуты!
- [sshwatch](https://github.com/marshyski/sshwatch) - IPS для SSH аналогичен DenyHosts, написанному на Python. Он также может собирать информацию о злоумышленнике во время атаки в журнале.
- [Stealth](https://fbb-git.github.io/stealth/) - Проверка целостности файла, которая практически не оставляет осадка. Контроллер запускается с другого компьютера, что затрудняет злоумышленнику узнать, что файловая система проверяется через определенные псевдослучайные интервалы по SSH. Настоятельно рекомендуется для малых и средних развертываний.
- [AIEngine](https://bitbucket.org/camp0/aiengine) - AIEngine - это интерактивное / программируемое средство проверки пакетов Python / Ruby / Java / Lua следующего поколения с возможностями обучения без какого-либо вмешательства человека, NIDS (обнаружение вторжений в сеть) Системный) функционал, классификация доменов DNS, сетевой коллектор, криминалистика сети и многое другое.
- [Denyhosts](http://denyhosts.sourceforge.net/) - Помешать атакам на основе словаря SSH и атакам методом перебора.
- [Fail2Ban](http://www.fail2ban.org/wiki/index.php/Main_Page) - сканирует файлы журналов и выполняет действия по IP-адресам, которые показывают вредоносное поведение.
- [SSHGuard](http://www.sshguard.net/) - программное обеспечение для защиты служб в дополнение к SSH, написанное на C
- [Lynis](https://cisofy.com/lynis/) - инструмент аудита безопасности с открытым исходным кодом для Linux / Unix.

## Honey Pot / Honey Net

- [awesome-honeypots](https://github.com/paralax/awesome-honeypots) - Канонический список потрясающих приманок.
- [HoneyPy](https://github.com/foospidy/HoneyPy) - HoneyPy - это приманка с низким и средним уровнем взаимодействия. Он предназначен для простого развертывания, расширения функциональности с помощью плагинов и применения пользовательских конфигураций.
- [Dionaea](https://www.edgis-security.org/honeypot/dionaea/). Предполагается, что Dionaea станет преемником nepenthes, внедряет python в качестве языка сценариев, использует libemu для обнаружения шелл-кодов, поддерживает ipv6 и tls.
- [Conpot](http://conpot.org/) - ICS / SCADA Honeypot. Conpot - это приманка для систем промышленного управления с низким уровнем интерактивности на стороне сервера, разработанная для простого развертывания, изменения и расширения. Предоставляя ряд общих протоколов управления производством, мы создали основы для создания собственной системы, способной эмулировать сложные инфраструктуры, чтобы убедить противника в том, что он только что нашел огромный промышленный комплекс. Чтобы улучшить возможности обмана, мы также предоставили возможность сервера настраивать пользовательский интерфейс «человек-машина», чтобы увеличить поверхность атаки «приманок». Время отклика сервисов может быть искусственно задержано, чтобы имитировать поведение системы при постоянной нагрузке. Поскольку мы предоставляем полные стеки протоколов, к Conpot можно получить доступ с помощью производительных HMI или расширить с помощью реального оборудования.
- [Amun](https://github.com/zeroq/amun) - Honeypot с низким уровнем взаимодействия на основе Python.
- [Glastopf](http://glastopf.org/) - Glastopf - это Honeypot, который эмулирует тысячи уязвимостей для сбора данных от атак, направленных на веб-приложения. Принцип, лежащий в основе этого, очень прост: ответьте на правильный ответ злоумышленнику, использующему веб-приложение.
- [Kippo](https://github.com/desaster/kippo) - Kippo - это медпот SSH со средним взаимодействием, предназначенный для регистрации атак с использованием грубой силы и, что наиболее важно, всего взаимодействия с оболочкой, выполняемого атакующим.
- [Kojoney](http://kojoney.sourceforge.net/) - Kojoney - это приманка для взаимодействия низкого уровня, эмулирующая SSH-сервер. Демон написан на Python с использованием библиотек Twisted Conch.
- [HonSSH](https://github.com/tnich/honssh) - HonSSH - это решение Honey Pot с высоким уровнем взаимодействия. HonSSH будет находиться между атакующим и медом, создавая две отдельные SSH-связи между ними.
- [Bifrozt](http://sourceforge.net/projects/bifrozt/) - Bifrozt - это устройство NAT с сервером DHCP, которое обычно развертывается с одним NIC, подключенным напрямую к Интернету, и одним NIC, подключенным к внутренней сети. Что отличает Bifrozt от других стандартных устройств NAT, так это его способность работать в качестве прозрачного прокси-сервера SSHv2 между злоумышленником и вашей приманкой. Если вы развернете SSH-сервер во внутренней сети Bifrozt, он запишет все взаимодействия в файл TTY в виде простого текста, который можно будет просмотреть позже, и получит копию всех загруженных файлов. Вам не нужно устанавливать какое-либо дополнительное программное обеспечение, компилировать какие-либо модули ядра или использовать определенную версию или тип операционной системы на внутреннем сервере SSH, чтобы это работало.
- [HoneyDrive](http://bruteforce.gr/honeydrive) - HoneyDrive - это лучший Linux-дистрибутив honeypot. Это виртуальное устройство (OVA) с установленной версией Xubuntu Desktop 12.04.4 LTS. Он содержит более 10 предустановленных и предварительно настроенных пакетов программного обеспечения honeypot, таких как honeyppot Kippo SSH, honeypot с вредоносным ПО Dionaea и Amun, honeypot с низким уровнем взаимодействия Honeyd, honeypot и Wordpot Glastopf, Honeypot Conpot SCADA / ICS, honeyclients Thug и PhoneyC и многое другое. , Кроме того, он включает в себя множество полезных предварительно настроенных сценариев и утилит для анализа, визуализации и обработки данных, которые он может захватывать, таких как Kippo-Graph, Honeyd-Viz, DionaeaFR, стек ELK и многое другое. Наконец, в дистрибутиве также присутствует почти 90 известных инструментов анализа вредоносных программ, криминалистики и мониторинга сети.
- [Cuckoo Sandbox](http://www.cuckoosandbox.org/) - Cuckoo Sandbox - это программное обеспечение с открытым исходным кодом для автоматизации анализа подозрительных файлов. Для этого используются пользовательские компоненты, которые отслеживают поведение вредоносных процессов при работе в изолированной среде.
- [T-Pot Honeypot Distro](http://dtag-dev-sec.github.io/mediator/feature/2017/11/07/t-pot-17.10.html) - T-Pot основан на сети установщик Ubuntu Server 16 / 17.x LTS. Демоны honeypot, а также другие используемые компоненты поддержки были упакованы в контейнеры с помощью Docker. Это позволяет нам запускать несколько демонов honeypot в одном сетевом интерфейсе, сохраняя при этом небольшую площадь и ограничивая каждую honeypot в пределах собственной среды. Установка поверх стандартной Ubuntu - [T-Pot Autoinstall(https://github.com/dtag-dev-sec/t-pot-autoinstall) - Этот скрипт установит T-Pot 16.04 / 17.10 на свежую Ubuntu 16.04.x LTS (64 бита). Он предназначен для использования на хост-серверах, где указан базовый образ Ubuntu и нет возможности устанавливать собственные образы ISO. Успешно протестирован на ванильной Ubuntu 16.04.3 в VMware.

- База данных Honeypots
    - [Delilah](https://github.com/SecurityTW/delilah) - Elasticsearch Honeypot, написанный на Python (родом из Novetta).
    - [ESPot](https://github.com/mycert/ESPot) - Приманка Elasticsearch, написанная на NodeJS, чтобы фиксировать все попытки использования CVE-2014-3120.
    - [Эластичный мед](https://github.com/jordan-wright/elastichoney) - Простой Elasticsearch Honeypot.
    - [HoneyMysql](https://github.com/xiaoxiaoleo/HoneyMysql) - Простой проект Mysql honeypot.
    - [MongoDB-HoneyProxy](https://github.com/Plazmaz/MongoDB-HoneyProxy) - MongoDB-посредник-приманка.
    - [MongoDB-HoneyProxyPy](https://github.com/jwxa2015/MongoDB-HoneyProxyPy) - MongoDB-посредник-приманка от python3.
    - [NoSQLpot](https://github.com/torque59/nosqlpot) - платформа Honeypot, построенная на базе данных в стиле NoSQL.
    - [mysql-honeypotd](https://github.com/sjinks/mysql-honeypotd) - Приманка MySQL с низким уровнем взаимодействия, написанная на C.
    - [MysqlPot](https://github.com/schmalle/MysqlPot) - HoneySQL, еще очень ранняя стадия.
    - [pghoney](https://github.com/betheroot/pghoney) - Постгресский Honeypot с низким уровнем взаимодействия.
    - [sticky_elephant](https://github.com/betheroot/sticky_elephant) - средний постпосадочный honeypot.

- веб-приманки
    - [Bukkit Honeypot](https://github.com/Argomirr/Honeypot) - Плагин Honeypot для Bukkit.
    - [EoHoneypotBundle](https://github.com/eymengunay/EoHoneypotBundle) - тип Honeypot для форм Symfony2.
    - [Glastopf](https://github.com/mushorg/glastopf) - Honeypot веб-приложения.
    - [Google Hack Honeypot](http://ghh.sourceforge.net) - Предназначен для проведения разведки против злоумышленников, которые используют поисковые системы в качестве инструмента взлома ваших ресурсов.
    - [Laravel Application Honeypot](https://github.com/msurguy/Honeypot) - Простой пакет защиты от спама для приложений Laravel.
    - [Nodepot](https://github.com/schmalle/Nodepot) - Honeypot веб-приложения NodeJS.
    - [Servletpot](https://github.com/schmalle/servletpot) - веб-приложение Honeypot.
    - [Shadow Daemon](https://shadowd.zecure.org/overview/introduction/) - Модульный брандмауэр веб-приложений / Honeypot с высоким уровнем взаимодействия для приложений PHP, Perl и Python.
    - [StrutsHoneypot](https://github.com/Cymmetria/StrutsHoneypot) - Struts на основе Apache 2, а также модуль обнаружения для серверов Apache 2.
    - [WebTrap](https://github.com/IllusiveNetworks-Labs/WebTrap) - предназначен для создания обманчивых веб-страниц для обмана и перенаправления злоумышленников с реальных сайтов.
    - [basic-auth-pot (bap)](https://github.com/bjeborn/basic-auth-pot) - Honeypot базовой аутентификации HTTP.
    - [bwpot](https://github.com/graneed/bwpot) - Хрупкие веб-приложения honeyPot.
    - [django-admin-honeypot](https://github.com/dmpayton/django-admin-honeypot) - Поддельный экран входа администратора Django для уведомления администраторов о попытке несанкционированного доступа.
    - [drupo](https://github.com/d1str0/drupot) - Drupal Honeypot.
    - [honeyhttpd](https://github.com/bocajspear1/honeyhttpd) - построитель honeypot на основе Python для веб-сервера.
    - [phpmyadmin_honeypot](https://github.com/gfoss/phpmyadmin_honeypot) - простая и эффективная приманка phpMyAdmin.
    - [shockpot](https://github.com/threatstream/shockpot) - WebApp Honeypot для обнаружения попыток эксплойта Shell Shock.
    - [smart-honeypot](https://github.com/freak3dot/smart-honeypot) - PHP-скрипт, демонстрирующий умный горшок с медом.
    - Snare / Tanner - преемники Гластопфа
        - [Snare](https://github.com/mushorg/snare) - Супер-реактивная приманка следующего поколения Super.
        - [Tanner](https://github.com/mushorg/tanner) - Оценка событий SNARE.
    - [stack-honeypot](https://github.com/CHH/stack-honeypot) - вставляет ловушку для спам-ботов в ответы.
    - [tomcat-manager-honeypot](https://github.com/helospark/tomcat-manager-honeypot) - Honeypot, имитирующий конечные точки менеджера Tomcat. Регистрирует запросы и сохраняет файл WAR злоумышленника для дальнейшего изучения.
    - WordPress honeypot
        - [HonnyPotter](https://github.com/MartinIngesen/HonnyPotter) - Приманка для входа в WordPress для сбора и анализа неудачных попыток входа.
        - [HoneyPress](https://github.com/dustyfresh/HoneyPress) - HoneyPot на основе Python в контейнере Docker.
        - [wp-smart-honeypot](https://github.com/freak3dot/wp-smart-honeypot) - плагин WordPress для уменьшения спама в комментариях с более умной приманкой.
        - [wordpot](https://github.com/gbrindisi/wordpot) - WordPress Honeypot.

- Сервис Honeypots
    - [ADBHoney](https://github.com/huuck/ADBHoney) - Honeypot с низким уровнем взаимодействия, имитирующий устройство Android, на котором выполняется процесс сервера Android Debug Bridge (ADB). 
    - [AMTHoneypot](https://github.com/packetflare/amthoneypot) - Honeypot для уязвимости микропрограммы Intel для микропрограммы AMT, CVE-2017-5689.
    - [Ensnare](https://github.com/ahoernecke/ensnare) - Простая установка Ruby honeypot.
    - [HoneyPy](https://github.com/foospidy/HoneyPy) - Honeypot с низким уровнем взаимодействия.
    - [Honeygrove](https://github.com/UHH-ISS/honeygrove) - Многоцелевая модульная приманка на основе Twisted.
    - [Honeyport](https://github.com/securitygeneration/Honeyport) - Простой honeyport, написанный на Bash и Python.
    - [Honeyprint](https://github.com/glaslos/honeyprint) - Honeypot для принтера.
    - [Lyrebird](https://hub.docker.com/r/lyrebird/honeypot-base/) - Современный высокопроизводительный фреймворк honeypot.
    - [MICROS honeypot](https://github.com/Cymmetria/micros_honeypot) - Honeypot с низким уровнем взаимодействия для обнаружения CVE-2018-2636 в компоненте Oracle Hospitality Simphony в приложениях Oracle Hospitality Applications (MICROS).
    - [RDPy](https://github.com/citronneur/rdpy) - Honeypot протокола удаленного рабочего стола Microsoft (RDP), реализованный в Python.
    - [Приманка для малого и среднего бизнеса](https://github.com/r0hi7/HoneySMB) - Приманка для сервиса SMB с высоким уровнем взаимодействия, способная захватывать вредоносное ПО, похожее на странствующее.
    - [Tom's Honeypot](https://github.com/inguardians/toms_honeypot) - Сладкий Python honeypot.
    - [Приманка WebLogic](https://github.com/Cymmetria/weblogic_honeypot) - Приманка с низким уровнем взаимодействия для обнаружения CVE-2017-10271 в компоненте Oracle WebLogic Server Oracle Fusion Middleware.
    - [WhiteFace Honeypot](https://github.com/csirtgadgets/csirtg-honeypot) - витая приманка для WhiteFace.
    - [honeycomb_plugins](https://github.com/Cymmetria/honeycomb_plugins) - хранилище плагинов для Honeycomb, фреймворка honeypot от Cymmetria.
    - [honeyntp](https://github.com/fygrave/honeyntp) - NTP logger / honeypot.
    - [honeypot-camera](https://github.com/alexbredo/honeypot-camera) - Наблюдение за камерой honeypot.
    - [honeypot-ftp](https://github.com/alexbredo/honeypot-ftp) - FTP Honeypot.
    - [honeytrap](https://github.com/honeytrap/honeytrap) - расширенная среда Honeypot, написанная на Go, которая может быть связана с другим программным обеспечением honeypot.
    - [pyrdp](https://github.com/gosecure/pyrdp) - RDP man-in-the-middle и библиотека для Python 3 с возможностью наблюдения за соединениями в реальном времени или по факту.
    - [troje](https://github.com/dutchcoders/troje/) - Honeypot, который запускает каждое соединение со службой в отдельном контейнере LXC.

- Распределенные Honeypots
    - [DemonHunter](https://github.com/RevengeComing/DemonHunter) - Honeypot-сервер с низким уровнем взаимодействия.

- Анти-Honeypot вещи
    - [kippo_detect](https://github.com/andrew-morris/kippo_detect) - оскорбительный компонент, который обнаруживает присутствие приманки kippo.

- ICS / SCADA honeypots
    - [Conpot](https://github.com/mushorg/conpot) - Honeypot ICS / SCADA.
    - [GasPot](https://github.com/sjhilt/GasPot) - Veeder Root Gaurdian AST, распространенный в нефтегазовой промышленности.
    - [SCADA honeynet](http://scadahoneynet.sourceforge.net) - Создание Honeypots для промышленных сетей.
    - [gridpot](https://github.com/sk4ld/gridpot) - Инструменты с открытым исходным кодом для реалистичного поведения электрических сетей.
    - [scada-honeynet](http://www.digitalbond.com/blog/2007/07/24/scada-honeynet-article-in-infragard-publication/) - имитирует многие сервисы из популярного ПЛК и лучше помогает исследователям SCADA понять потенциальные риски, связанные с открытыми устройствами системы управления.

- Другое / случайное
    - [Чертовски простой Honeypot (DSHP)](https://github.com/naorlivne/dshp) - Каркас Honeypot с подключаемыми обработчиками.
    - [NOVA](https://github.com/DataSoft/Nova) - использует honeypots в качестве детекторов, выглядит как законченная система.
    - [OpenFlow Honeypot (OFPot)](https://github.com/upa/ofpot) - Перенаправляет трафик для неиспользуемых IP-адресов в honeypot, построенный на POX.
    - [OpenCanary](https://github.com/thinkst/opencanary) - Модульный и децентрализованный демон honeypot, который запускает несколько канарских версий сервисов и предупреждает, когда сервис (ab) используется.
    - [ciscoasa_honeypot](https://github.com/cymmetria/ciscoasa_honeypot) Honeypot с низким уровнем взаимодействия для компонента Cisco ASA, способного обнаруживать CVE-2018-0101, уязвимость DoS и удаленного выполнения кода. 
    - [miniprint](https://github.com/sa7mon/miniprint) - Honeypot принтера со средним взаимодействием.

- Ботнет C2 инструменты
    - [Hale](https://github.com/pjlantz/Hale) - Монитор управления и контроля ботнета.
    - [dnsMole](https://code.google.com/archive/p/dns-mole/) - анализирует трафик DNS и потенциально обнаруживает команды ботнета и контролирует активность сервера, а также зараженные хосты.

- средство обнаружения атак IPv6
    - [ipv6-атакующий детектор](https://github.com/mzweilin/ipv6-attack-detector/) - проект Google Summer of Code 2012, поддерживаемый организацией Honeynet Project.

- инструментарий динамического кода
    - [Frida](https://www.frida.re) - добавьте JavaScript для изучения нативных приложений на Windows, Mac, Linux, iOS и Android.

- Инструмент для конвертирования сайта в серверные приманки
    - [HIHAT](http://hihat.sourceforge.net/) - Преобразование произвольных приложений PHP в веб-интерфейсы Honeypots с высоким уровнем взаимодействия.

- сборщик вредоносных программ
    - [Kippo-Malware](https://bruteforcelab.com/kippo-malware) - скрипт Python, который загружает все вредоносные файлы, хранящиеся в виде URL-адресов в базе данных honeypot Kippo SSH.

- Распределенный датчик развертывания
    - [Modern Honey Network](https://github.com/threatstream/mhn) - Управление датчиками с множественным фырканьем и honeypot, использует сеть виртуальных машин, небольшие установки SNORT, скрытые дионеи и централизованный сервер для управления.

- Инструмент сетевого анализа
    - [Tracexploit](https://code.google.com/archive/p/tracexploit/) - воспроизведение сетевых пакетов.

- Журнал анонимайзера
    - [LogAnon](http://code.google.com/archive/p/loganon/) - Библиотека анонимной регистрации, которая помогает обеспечить согласованность анонимных журналов между журналами и захватами сети.

- Honeypot с низким уровнем взаимодействия (задняя дверь маршрутизатора)
    - [Honeypot-32764](https://github.com/knalli/honeypot-for-tcp-32764) - Honeypot для черного хода маршрутизатора (TCP 32764).
    - [WAPot](https://github.com/lcashdol/WAPot) - Honeypot, который можно использовать для наблюдения за трафиком, направленным на домашние маршрутизаторы.

- перенаправитель трафика фермы Honeynet
    - [Honeymole](https://web.archive.org/web/20100326040550/http://www.honeynet.org.pt:80/index.php/HoneyMole) - развертывание нескольких датчиков, которые перенаправляют трафик в централизованную коллекцию медовых горшков.

- HTTPS Proxy
    - [mitmproxy](https://mitmproxy.org/) - позволяет перехватывать, проверять, изменять и воспроизводить потоки трафика.

- Системная аппаратура
    - [Sysdig](https://sysdig.com/opensource/) - Исследование на уровне системы с открытым исходным кодом позволяет регистрировать состояние и активность системы из запущенного экземпляра GNU / Linux, а затем сохранять, фильтровать и анализировать результаты.
    - [Fibratus](https://github.com/rabbitstack/fibratus) - Инструмент для исследования и отслеживания ядра Windows.

- Honeypot для распространения вредоносного ПО через USB
    - [Ghost-usb](https://github.com/honeynet/ghost-usb-honeypot) - Honeypot для вредоносных программ, распространяющихся через запоминающие устройства USB.

- Сбор данных
    - [Kippo2MySQL](https://bruteforcelab.com/kippo2mysql) - извлекает некоторые очень простые статистические данные из текстовых файлов журналов Kippo и вставляет их в базу данных MySQL.
    - [Kippo2ElasticSearch](https://bruteforcelab.com/kippo2elasticsearch) - сценарий Python для передачи данных из базы данных MySQL Kippo SSH honeypot в экземпляр ElasticSearch (сервер или кластер).

- Парсер фреймворка пассивного сетевого аудита
    - [Инфраструктура пассивного сетевого аудита (pnaf)] (https://github.com/jusafing/pnaf) - платформа, которая объединяет несколько пассивных и автоматических методов анализа для обеспечения оценки безопасности сетевых платформ.

- VM мониторинг и инструменты
    - [Antivmdetect](https://github.com/nsmfoo/antivmdetection) - Скрипт для создания шаблонов для использования с VirtualBox, чтобы сделать обнаружение ВМ более сложным.
    - [VMCloak](https://github.com/hatching/vmcloak) - Автоматическое создание виртуальной машины и маскировка для песочницы с кукушкой.
    - [vmitools] (http://libvmi.com/) - библиотека C с привязками Python, которая позволяет легко отслеживать низкоуровневые детали работающей виртуальной машины.

- бинарный отладчик
    - [Hexgolems - серверная часть отладчика Pint](https://github.com/hexgolems/pint) - серверная часть отладчика и оболочка LUA для PIN-кода.
    - [Hexgolems - внешний интерфейс отладчика Schem](https://github.com/hexgolems/schem) - внешний интерфейс отладчика.

- Мобильный инструмент анализа
    - [Androguard](https://github.com/androguard/androguard) - Обратный инжиниринг, анализ вредоносных программ и программных продуктов для приложений Android и многое другое.
    - [APKinspector](https://github.com/honeynet/apkinspector/) - мощный инструмент с графическим интерфейсом для аналитиков для анализа приложений Android.

- Honeypot с низким уровнем взаимодействия
    - [Honeyperl](https://sourceforge.net/projects/honeyperl/) - Программное обеспечение Honeypot, основанное на Perl, с плагинами, разработанными для многих функций, таких как: wingates, telnet, squid, smtp и т. Д.
    - [T-Pot](https://github.com/dtag-dev-sec/tpotce) - Устройство «все в одном» от оператора связи T-Mobile

- Слияние данных Honeynet
    - [HFlow2](https://projects.honeynet.org/hflow) - инструмент объединения данных для анализа сети / медоносной сети.

- сервер
    - [Amun](http://amunhoney.sourceforge.net) - Honeypot эмуляции уязвимости.
    - [artillery](https://github.com/trustedsec/artillery/) - инструмент синей команды с открытым исходным кодом, предназначенный для защиты операционных систем Linux и Windows несколькими способами.
    - [Bait and Switch](http://baitnswitch.sourceforge.net) - перенаправляет весь враждебный трафик на honeypot, который частично отражает вашу производственную систему.
    - [HoneyWRT](https://github.com/CanadianJeff/honeywrt) - Приманка Python с низким уровнем взаимодействия, разработанная для имитации сервисов или портов, которые могут стать целью для злоумышленников.
    - [Honeyd](https://github.com/provos/honeyd) - См. [Honeyd tools] (# honeyd-tools).
    - [Honeysink](http://www.honeynet.org/node/773) - провал в сети с открытым исходным кодом, который обеспечивает механизм для обнаружения и предотвращения вредоносного трафика в данной сети.
    - [Hontel](https://github.com/stamparm/hontel) - Telnet Honeypot.
    - [KFSensor](http://www.keyfocus.net/kfsensor/) - Система обнаружения вторжений honeypot (IDS) на базе Windows.
    - [LaBrea](http://labrea.sourceforge.net/labrea-info.html) - захватывает неиспользуемые IP-адреса и создает виртуальные серверы, привлекательные для червей, хакеров и других пользователей Интернета.
    - [MTPot](https://github.com/Cymmetria/MTPot) - Telnet Honeypot с открытым исходным кодом, ориентированный на вредоносное ПО Mirai.
    - [SIREN](https://github.com/blaverick62/SIREN) - Полуинтеллектуальная сеть HoneyPot - Интеллектуальная виртуальная среда HoneyNet.
    - [TelnetHoney](https://github.com/balte/TelnetHoney) - Простая приманка telnet.
    - [UDPot Honeypot](https://github.com/jekil/UDPot) - Простые сценарии UDP / DNS honeypot.
    - [Еще одна поддельная приманка (YAFH)](https://github.com/fnzv/YAFH) - Простая приманка, написанная на Go.
    - [арктическая ласточка](https://github.com/ajackal/arctic-swallow) - Honeypot с низким уровнем взаимодействия.
    - [обжора](https://github.com/mushorg/glutton) - Все едят honeypot.
    - [go-HoneyPot](https://github.com/Mojachieee/go-HoneyPot) - сервер Honeypot, написанный на Go.
    - [go-emulators](https://github.com/kingtuna/go-emulators) - Эмуляторы Honeypot Golang.
    - [honeymail](https://github.com/sec51/honeymail) - приманка SMTP, написанная на Голанге.
    - [honeytrap](https://github.com/tillmannw/honeytrap) - Honeypot с низким уровнем взаимодействия и инструмент сетевой безопасности, написанный для ловли атак на службы TCP и UDP.
    - [imap-honey](https://github.com/yvesago/imap-honey) - приманка IMAP, написанная на Голанге.
    - [mwcollectd](https://www.openhub.net/p/mwcollectd) - универсальный демон сбора вредоносных программ, объединяющий в себе лучшие функции nepenthes и honeytrap.
    - [potd](https://github.com/lnslbrty/potd) - Высоко масштабируемая приманка SSH / TCP с низким и средним взаимодействием, разработанная для устройств OpenWrt / IoT, использующая несколько функций ядра Linux, таких как пространства имен, seccomp и возможности потоков ,
    - [portlurker](https://github.com/bartnv/portlurker) - прослушиватель портов в Rust с угадыванием протокола и безопасным отображением строк.
    - [slipm-honeypot](https://github.com/rshipp/slipm-honeypot) - Простой honeypot для мониторинга портов с низким уровнем взаимодействия.
    - [telnet-iot-honeypot](https://github.com/Phype/telnet-iot-honeypot) - Python telnet honeypot для ловли двоичных файлов ботнетов.
    - [telnetlogger](https://github.com/robertdavidgraham/telnetlogger) - приманка Telnet, предназначенная для отслеживания ботнета Mirai.
    - [vnclowpot](https://github.com/magisterquis/vnclowpot) - Honeypot с низким уровнем взаимодействия VNC.


- Генерация подписи IDS
    - [Honeycomb](http://www.icir.org/christian/honeycomb/) - Автоматическое создание подписи с использованием honeypots.

- Служба поиска номеров и префиксов AS
    - [CC2ASN](http://www.cc2asn.com/) - Простой сервис поиска номеров AS и префиксов, принадлежащих любой стране мира.

- Сбор данных / обмен данными
    - [HPfriends](http://hpfriends.honeycloud.net/#/home) - Платформа обмена данными Honeypot.
        - [hpfriends - обмен социальными данными в режиме реального времени](https://heipei.io/sigint-hpfriends/) - Презентация о системе подачи HPFriends 
    - [HPFeeds](https://github.com/rep/hpfeeds/) - Легкий аутентифицированный протокол публикации-подписки.

- Центральный инструмент управления
    - [PHARM](http://www.nepenthespharm.com/) - Управляйте, сообщайте и анализируйте свои распределенные экземпляры Nepenthes.

- Анализатор сетевого подключения
    - [Impost](http://impost.sourceforge.net/) - инструмент аудита сетевой безопасности, предназначенный для анализа криминалистических данных за скомпрометированными и / или уязвимыми демонами. 

- Развертывание Honeypot
    - [Современная сеть Honeynet](http://threatstream.github.io/mhn/) - Оптимизирует развертывание и управление безопасными honeypots.

- Расширения Honeypot для Wireshark
    - [Расширения Whireshark](https://www.honeynet.org/project/WiresharkExtensions) - Применение правил и подписей Snort IDS к файлам захвата пакетов с помощью Wireshark.


- Клиент
    - [CWSandbox / GFI Sandbox](https://www.gfi.com/products-and-solutions/all-products)
    - [Capture-HPC-Linux](https://redmine.honeynet.org/projects/linux-capture-hpc/wiki)
    - [Capture-HPC-NG](https://github.com/CERT-Polska/HSN-Capture-HPC-NG)
    - [Capture-HPC](https://projects.honeynet.org/capture-hpc) - Honeypot клиента с высоким уровнем взаимодействия (также называемый honeyclient).
    - [HoneyBOT](http://www.atomicsoftwaresolutions.com/)
    - [HoneyC](https://projects.honeynet.org/honeyc)
    - [HoneySpider Network](https://github.com/CERT-Polska/hsn2-bundle) - Высоко масштабируемая система, объединяющая несколько клиентских приманок для обнаружения вредоносных веб-сайтов.
    - [HoneyWeb](https://code.google.com/archive/p/gsoc-honeyweb/) - веб-интерфейс, созданный для управления и удаленного обмена ресурсами Honeyclients. 
    - [Jsunpack-n](https://github.com/urule99/jsunpack-n)
    - [MonkeySpider](http://monkeyspider.sourceforge.net)
    - [PhoneyC](https://github.com/honeynet/phoneyc) - медленный клиент Python (позже замененный Thug).
    - [Pwnypot](https://github.com/shjalayeri/pwnypot) - Honeypot клиента с высоким уровнем взаимодействия.
    - [Rumal](https://github.com/thugs-rumal/) - Rumāl Thug's: платье и оружие Thug's.
    - [shelia](https://www.cs.vu.nl/~herbertb/misc/shelia/) - Приманка на стороне клиента для обнаружения атак.
    - [Thug] (https://buffer.github.io/thug/) - медленный клиент с низким уровнем взаимодействия на основе Python.
    - [Очередь распределенных задач Thug](https://thug-distributed.readthedocs.io/en/latest/index.html)
    - [Тригона](https://www.honeynet.org/project/Trigona)
    - [URLQuery](https://urlquery.net/)
    - [YALIH (еще один медленный клиент с низким уровнем взаимодействия)](https://github.com/Masood-M/yalih) - приманка для клиентов с низким уровнем взаимодействия, предназначенная для обнаружения вредоносных веб-сайтов с помощью методов подписи, аномалий и сопоставления с образцом.

- Горшок меда
    - [Инструмент обмана](http://www.all.net/dtk/dtk.html)
    - [IMHoneypot](https://github.com/mushorg/imhoneypot)

- PDF документ инспектор
    - [peepdf](https://github.com/jesparza/peepdf) - Мощный инструмент Python для анализа PDF-документов.

- Гибридная приманка с низким / высоким взаимодействием
    - [HoneyBrid](http://honeybrid.sourceforge.net)

- SSH Honeypots
    - [Blacknet](https://github.com/morian/blacknet) - Система с несколькими головками SSH honeypot.
    - [Cowrie](https://github.com/cowrie/cowrie) - Cowrie SSH Honeypot (на основе kippo).
    - [Докер DShield](https://github.com/xme/dshield-docker) - Контейнер Docker, на котором запущена задатка с включенным выводом DShield.
    - [HonSSH](https://github.com/tnich/honssh) - регистрирует все соединения SSH между клиентом и сервером.
    - [HUDINX](https://github.com/Cryptix720/HUDINX) - Крошечное взаимодействие SSH-приманка, разработанная в Python для регистрации атак методом перебора и, что наиболее важно, всего взаимодействия с оболочкой, выполняемого атакующим.
    - [Kippo](https://github.com/desaster/kippo) - Приманка SSH со средним взаимодействием.
    - [Kippo_JunOS](https://github.com/gregcmartin/Kippo_JunOS) - Kippo настроен как задний экран.
    - [Kojoney2](https://github.com/madirish/kojoney2) - Honeypot с низким уровнем взаимодействия SSH, написанный на Python и основанный на коджени Хосе Антонио Коретом.
    - [Kojoney](http://kojoney.sourceforge.net/) - Honeypot с низким уровнем взаимодействия на основе Python, эмулирующий SSH-сервер, реализованный с помощью Twisted Conch.
    - [Анализ логов LongTail @ Marist College](http://longtail.it.marist.edu/honey/) - Анализ логов SSH приманки.
    - [Malbait](https://github.com/batchmcnulty/Malbait) - Простая приманка TCP / UDP, реализованная в Perl.
    - [MockSSH](https://github.com/ncouture/MockSSH) - Создайте макет сервера SSH и определите все команды, которые он поддерживает (Python, Twisted).
    - [cowrie2neo](https://github.com/xlfe/cowrie2neo) - анализировать журналы honeypot cowrie в базе данных neo4j.
    - [go-sshoney](https://github.com/ashmckenzie/go-sshoney) - Honeypot SSH.
    - [go0r](https://github.com/fzerorubigd/go0r) - Простая ssh honeypot на Голанге.
    - [gohoney](https://github.com/PaulMaddox/gohoney) - приманка SSH, написанная на Go.
    - [hived](https://github.com/sahilm/hived) - Honeypot на основе Голанга.
    - [hnypots-agent)](https://github.com/joshrendek/hnypots-agent) - SSH-сервер в Go, который регистрирует комбинации имени пользователя и пароля.
    - [honeypot.go](https://github.com/mdp/honeypot.go) - Honeypot SSH, написанный на Go.
    - [honeyssh](https://github.com/ppacher/honeyssh) - учетная запись сброса приманки SSH со статистикой.
    - [hornet](https://github.com/czardoz/hornet) - Приманка среднего уровня SSH, поддерживающая несколько виртуальных хостов.
    - [ssh-auth-logger](https://github.com/JustinAzoff/ssh-auth-logger) - Honeypot ведения журнала аутентификации SSH с низким / нулевым взаимодействием.
    - [ssh-honeypot](https://github.com/droberson/ssh-honeypot) - Поддельный sshd, который регистрирует IP-адреса, имена пользователей и пароли.
    - [ssh-honeypot](https://github.com/amv42/sshd-honeypot) - модифицированная версия демона OpenSSH, который перенаправляет команды в Cowrie, где все команды интерпретируются и возвращаются.
    - [ssh-honeypotd](https://github.com/sjinks/ssh-honeypotd) - Honeypot с низким уровнем взаимодействия SSH, написанный на C.
    - [sshForShits](https://github.com/traetox/sshForShits) - Фреймворк для высокопроизводительного SSH-приманки.
    - [sshesame](https://github.com/jaksi/sshesame) - фальшивый SSH-сервер, который позволяет всем входить и регистрировать свою активность.
    - [sshhipot](https://github.com/magisterquis/sshhipot) - Приманка MitM SSH с высокой степенью взаимодействия.
    - [sshlowpot](https://github.com/magisterquis/sshlowpot) - Еще один не требующий излишеств приманки SSH с низким уровнем взаимодействия в Go.
    - [sshsyrup](https://github.com/mkishere/sshsyrup) - Простой SSH Honeypot с функциями для захвата активности терминала и загрузки на asciinema.org.
    - [витые приманки](https://github.com/lanjelot/twisted-honeypots) - приманки SSH, FTP и Telnet на основе Twisted.

- Распределенный датчик проекта
    - [Проект DShield Web Honeypot](https://sites.google.com/site/webhoneypotsite/)

- анализатор pcap
    - [Honeysnap](https://projects.honeynet.org/honeysnap/)

- Перенаправитель сетевого трафика
    - [Honeywall](https://projects.honeynet.org/honeywall/)

- Honeypot Distribution со смешанным содержимым
    - [HoneyDrive](https://bruteforcelab.com/honeydrive)

- Датчик Honeypot
    - [Honeeepi](https://redmine.honeynet.org/projects/honeeepi/wiki) - Датчик Honeypot на Raspberry Pi на основе настроенной Raspbian OS.

- Резьба по файлу
    - [TestDisk & PhotoRec](https://www.cgsecurity.org/)

- Инструмент поведенческого анализа для win32
    - [Capture BAT](https://www.honeynet.org/node/315)

- Live CD
    - [DAVIX](https://www.secviz.org/node/89) - DAVIX Live CD.

- Spamtrap
    - [Mail :: SMTP :: Honeypot](https://metacpan.org/pod/release/MIKER/Mail-SMTP-Honeypot-0.11/Honeypot.pm) - модуль Perl, обеспечивающий функциональность стандартного SMTP сервер.
    - [Mailoney](https://github.com/awhitehatter/mailoney) - SMTP honeypot, Open Relay, Cred Harvester, написанный на python.
    - [SendMeSpamIDS.py](https://github.com/johestephan/VerySimpleHoneypot) - Простой SMTP-выбор всех IDS и анализатора.
    - [Шива](https://github.com/shiva-spampot/shiva) - Спам Honeypot с интеллектуальным виртуальным анализатором.
        - [Шива Советы и хитрости по борьбе со спамом для его запуска и работы] (https://www.pentestpartners.com/security-blog/shiva-the-spam-honeypot-tips-and-tricks-for-getting-it -up-и-запуск /)
    - [SpamHAT](https://github.com/miguelraulb/spamhat) - Инструмент для борьбы со спамом.
    - [Spamhole](http://www.spamhole.net/)
    - [honeypot](https://github.com/jadb/honeypot) - Неофициальный PHP SDK проекта Honey Pot.
    - [spamd](http://man.openbsd.org/cgi-bin/man.cgi?query=spamd%26apropos=0%26sektion=0%26manpath=OpenBSD+Current%26arch=i386%26format=html)

- Коммерческая HONEY сеть
    - [Cymmetria Mazerunner](https://cymmetria.com/products/mazerunner/) - отводит злоумышленников от реальных целей и создает след атаки.

## Руководства

- [T-Pot: платформа для нескольких приманок](https://dtag-dev-sec.github.io/mediator/feature/2015/03/17/concept.html)
- [Сценарий установки Honeypot (Dionaea и kippo)](https://github.com/andrewmichaelsmith/honeypot-setup-script/)

- Развертывание
    - [Dionaea и EC2 за 20 минут](http://andrewmichaelsmith.com/2012/03/dionaea-honeypot-on-ec2-in-20-minutes/) - Учебное пособие по настройке Dionaea в экземпляре EC2.
    - [Использование приманки Raspberry Pi для передачи данных в DShield / ISC] (https://isc.sans.edu/diary/22680) - Система на основе Raspberry Pi позволит нам поддерживать одну кодовую базу, которая упростит собирать расширенные журналы за пределами журналов брандмауэра.
    - [honeypotpi](https://github.com/free5ty1e/honeypotpi) - Скрипт для превращения Raspberry Pi в HoneyPot Pi.

- Научно-исследовательские работы
    - [Исследовательские работы Honeypot](https://github.com/shbhmsingh72/Honeypot-Research-Papers) - PDF-файлы исследовательских работ по honeypots.
    - [vEYE](https://link.springer.com/article/10.1007%2Fs10115-008-0137-3) - Поведенческие следы для самораспространяющегося обнаружения и профилирования червя.
