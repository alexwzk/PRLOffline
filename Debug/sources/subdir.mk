################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../sources/murmurHash3.cpp 

OBJS += \
./sources/murmurHash3.o 

CPP_DEPS += \
./sources/murmurHash3.d 


# Each subdirectory must supply rules for building sources it contributes
sources/%.o: ../sources/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -I/usr/local/openssl/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


