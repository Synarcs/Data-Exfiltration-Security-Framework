/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

#include <stdio.h>
#include <iostream>
#include <memory>

#include "hdrs/feature.hpp"


int main() {
    std::string domain = "mail.google.com";
    
    std::unique_ptr<LocalInferenceTest::FeatureLoaderExtractor> feature = 
                            std::make_unique<LocalInferenceTest::FeatureLoaderExtractor>();
    
    feature.get()->infer(domain);
}