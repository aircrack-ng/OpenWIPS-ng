################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../sensor/packet_assembly.c 

OBJS += \
./sensor/packet_assembly.o 

C_DEPS += \
./sensor/packet_assembly.d 


# Each subdirectory must supply rules for building sources it contributes
sensor/%.o: ../sensor/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


