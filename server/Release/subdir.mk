################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../command_parse.c \
../config.c \
../main.c \
../rpcap_server.c \
../sensor.c \
../users.c 

OBJS += \
./command_parse.o \
./config.o \
./main.o \
./rpcap_server.o \
./sensor.o \
./users.o 

C_DEPS += \
./command_parse.d \
./config.d \
./main.d \
./rpcap_server.d \
./sensor.d \
./users.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


