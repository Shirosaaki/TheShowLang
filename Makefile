#==============================================
 #                main.c
 #  main
 #  Author: shirosaaki
 #  Date: 2025-10-23
 #=============================================

SRC	=	${wildcard src/*.c}

OBJ	=	${SRC:.c=.o}

BIN_DIR = bin

all: ${BIN_DIR}/tsc

${BIN_DIR}/tsc: src/tsc.c | ${BIN_DIR}
	$(CC) -std=c11 -O2 -o $@ src/tsc.c

${BIN_DIR}:
	mkdir -p ${BIN_DIR}

clean:
	rm -f ${OBJ}

fclean:	clean
	rm -f ${BIN_DIR}/tsc

re:	fclean all
