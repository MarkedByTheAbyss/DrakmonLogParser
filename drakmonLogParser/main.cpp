// drakmonLogParser.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
// 

#include <iostream>
#include "drakmonLogParser.h"
#include "ArgParser.h"

int StartParser(drakmonLogParser* parser)
{
    time_t start = time(nullptr);
    parser->LoadPreInstProcs();
    parser->SortProcesses();

    time_t end = time(nullptr);
    std::cout << "\nProcess tree built, procesess sorted into new file.";
    std::cout << "\nWork time: " << end - start << " seconds!\n" << std::endl;

    start = end;
    parser->AnalyzeProcessTree();
    end = time(nullptr);
    std::cout << "\nProcess tree analysis complete.";
    std::cout << "\nWork time: " << end - start << " seconds!\n" << std::endl;
    return 0;
}

int SetArgs(drakmonLogParser* logParser, ArgParser* argParser)
{
    if (argParser->Contains("-preinstPath"))
        logParser->SetPreinstPath(argParser->Get("-preinstPath"));
    if (argParser->Contains("-logPath"))
        logParser->SetLogPath(argParser->Get("-logPath"));
    if (argParser->Contains("-recordDir"))
        logParser->SetRecordDirPath(argParser->Get("-recordDir"));
    if (argParser->Contains("-rulesPath"))
        logParser->SetRulesPath(argParser->Get("-rulesPath"));

    return 0;
}

void ShowHelp()
{
    std::cout << "-h (--help, -help) - Show help" << std::endl;
    std::cout << "-preinstPath - path to json file with preinstalled processes (PID, ProcessName, Path)" << std::endl;
    std::cout << "-logPath - path to drakmon log" << std::endl;
    std::cout << "-recordDir - path to dir where records will be created" << std::endl;
    std::cout << "-rulesPath - path to YARA rules file (must end with \\\\ or /)" << std::endl;
    std::cout << "Created by Deniska and BoBaH" << std::endl;

}

int main(int argc, char** argv)
{
    ArgParser* argParser = new ArgParser();
    drakmonLogParser* logParser = new drakmonLogParser();

    for (int i = 0; i < argc; i++)
    {
        string curArg(argv[i]);
        argParser->Insert(curArg);
    }

    if (argParser->IsHelp())
    {
        ShowHelp();
    }
    else
    {
        SetArgs(logParser, argParser);
        StartParser(logParser);
    }

    return 0;
}

/*

1. Process tree (создание задач с дропнутыми файлами) - PID/PPID
2. Log parser (JSON?)
3. Обработка инфы правилами (YARA?)
4. Эвристический анализатор
5. Формирование вывода (вердикт, сработавшие правила) - stdout/БД/Файл


Цикл:
    1. Пройти по логу и построить дерево + NtCreateUserProcess (базовые правила на создание 
        процессов, дроп файлов и запуск задач) 
    2. Распарсить нужные строки в логе - поиск интересных объектов(?)
    3. Обработать интересующие нас объекты с помощью правил
    4. Выдать вердикт по обработанным объектам (сработавшие правила, оценка эвристики,
        вердикт по процессу)
    5. Эвристический анализ должен учитывать, что правило сработало на конкретном процессе 
        (учитывать базовую информацию о самом процессе (системный, +-безопасный и т.д.)
            
Структуры:
    1. Дерево для процессов (ProcessTree):
        - PID
        - PPID
        - Process/File Name
        - LineNum
        - Структура 1.1. // распарсить комманд лайн и отправить инфу в структуру 1.1.
        - isPreInstalled? (множество системных PID'ов + множество 
            предуст. процессов (Name/paths))
        - foundFlags - map(flagName, count)

    1.1. Структура для дропнутых файлов (множество)
        - DroppedFileName
        - FilePath
        - isStarted
        - PID

    1.2. Структура - множество предустановленных процессов
        - PreInstalledFileName
            - ProcessName (string)
            - PID
            - Path
        
    2. Log parser
        Вспомогательный сканер, обрабатывающий JSON-строку (целиком) с помощью YARA
            + допольнителых условий + запоминание сработавших правил с 
            важной интересующей нас информацией с возможной дообработкой в отдельном
            потоке. 
            Если у правила есть определенный тег, ему требуется дообработка
            в специально выделенном методе. 

    3. Эвристический анализатор
        
       
    4. Структура файла с эвристиками
        - Вектор атаки 1
            - "Вирусная запись"
            - Трешхолд веса 1
                - Правило 1
                    - Вес
                    - Зависимость
                    - Наследуемость
                - Правило 2
                    - Вес
                    - Зависимость
                    - Количество
                    - Наследуемость

        - Вектор атаки 2
            - "Вирусная запись"
            - Трешхолд веса 2
                - Правило 1
                    - Вес
                    - Зависимость
                    - Наследуемость
                - Правило 2
                    - Вес
                    - Зависимость
                    - Количество
                    - Наследуемость


Находим объект
Ищем PPID текущего объекта в дереве как PID
Если PPID есть в дереве как PID процесса
    Добавляем этому PPID текущий объект как ребенка
    Записываем ребенку PPID

*/