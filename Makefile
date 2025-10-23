#==============================================
 #                main.c
 #  main
 #  Author: shirosaaki
 #  Date: 2025-10-23
 #=============================================

SRC	=	${wildcard src/*.c}

OBJ	=	${SRC:.c=.o}

all:	${OBJ}
	gcc -o tcs ${OBJ}

clean:
	rm -f ${OBJ}

fclean:	clean
	rm -f tcs

re:	fclean all
