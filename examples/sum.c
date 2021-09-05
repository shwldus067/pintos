#include <syscall.h> 
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv){
	int num1, num2, num3, num4;
	num1=atoi(argv[1]);
	num2=atoi(argv[2]);
	num3=atoi(argv[3]);
	num4=atoi(argv[4]);

	int result_fib=fibonacci(num1);
	int result_sum=sum_of_four_int(num1, num2, num3, num4);

	printf("%d %d\n", result_fib, result_sum);
	return EXIT_SUCCESS;
}
