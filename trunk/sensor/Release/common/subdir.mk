################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../common/client.c \
../common/pcap.c \
../common/server-client.c \
../common/server.c \
../common/sockets.c 

OBJS += \
./common/client.o \
./common/pcap.o \
./common/server-client.o \
./common/server.o \
./common/sockets.o 

C_DEPS += \
./common/client.d \
./common/pcap.d \
./common/server-client.d \
./common/server.d \
./common/sockets.d 


# Each subdirectory must supply rules for building sources it contributes
common/%.o: ../common/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


