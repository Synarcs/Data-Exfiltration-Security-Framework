/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

#include <stdio.h>
#include <iostream>
#include <memory>

#include "feature.hpp"

using namespace std;

int main(int *argc, char **argv) {
    std::string domain = "mail.google.com";
    
    unique_ptr<LocalInferenceTest::FeatureLoaderExtractor> feature = 
                            make_unique<LocalInferenceTest::FeatureLoaderExtractor>();
    
    feature.get()->infer(domain);
}