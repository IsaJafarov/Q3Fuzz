#! /usr/bin/env python
import os
import util
import argparse
from collections import Counter


def analyze_pcap_files_in_directory(directory):
    # Check if the directory exists
    if not os.path.isdir(directory):
        print(f"Directory '{directory}' does not exist.")
        return
    
    quic_messages_all = []
    # List all files in the directory
    for filename in os.listdir(directory):
        # Process only .pcapng files
        if filename.endswith(".pcapng"):
            quic_messages_hrf = ''
            file_path = os.path.join(directory, filename)
            # 1. Read and extract QUIC packets.
            try:
                # print(f"Reading file: {file_path}")
                quic_packets = util.h3msg_from_pcap(file_path, client_only=True)
            except Exception as e:
                print(f"Failed to read {filename}: {e}")
            # 2. Parse it.
            
            for quic_packet in quic_packets:
                # Convert each packet into human-readable format.
                message_hrf = util.h3msg_to_str(quic_packet)
                message_hrf = message_hrf.replace("PADDING,", "")
                message_hrf = message_hrf.replace(",PADDING", "")  
                message_hrf = message_hrf.replace("PING,", "")
                message_hrf = message_hrf.replace(",PING", "")

                """
                # CASE: Single HANDSHAKE without any argument. This is because of the missing SSLKEYLOG.
                ./sample_traffics/op_o_cdy_o.pcapng
                ./sample_traffics/op_o_ols_n.pcapng
                ./sample_traffics/ch_o_h2o_o.pcapng
                ./sample_traffics/ch_o_ols_o.pcapng
                ./sample_traffics/op_o_ng_o.pcapng
                ./sample_traffics/op_o_cdy_n.pcapng
                ./sample_traffics/ch_o_ng_n.pcapng
                ./sample_traffics/ch_o_ng_o.pcapng
                ./sample_traffics/ch_o_cdy_n.pcapng
                ./sample_traffics/op_o_h2o_n.pcapng
                
                if message_hrf == "[Q]HANDSHAKE":
                    print(file_path)
                    print(message_hrf)
                """

                """
                # CASE: Single QDS
                # This happens in the case of some ols. This is because of the seprated transimission of QES and QDS.
                ./sample_traffics/op_n_ols_o.pcapng
                ./sample_traffics/op_o_ols_o.pcapng
                ./sample_traffics/ch_o_ols_n.pcapng
                ./sample_traffics/op_n_ols_n.pcapng
                ./sample_traffics/ch_n_ols_o.pcapng
                ./sample_traffics/ch_n_ols_n.pcapng

                if message_hrf.find("[Q]1-RTT(ACK,STREAM) [H3]QPACK_DECODER_STREAM") == 0:
                    print(file_path)
                    print(message_hrf)
                """
                quic_messages_hrf += message_hrf
                quic_messages_hrf += '|'


            quic_messages_all.append(quic_messages_hrf[:-1])

    # for quic_message in quic_messages_all:
    #     print(quic_message)

    return quic_messages_all

def count_unique_elements_in_sequences(quic_message_all):
    element_counter = Counter()

    # 각 시퀀스에서 요소를 추출하여 카운트
    for sequence in quic_message_all:
        # 바(|)로 구분된 각 요소를 분리
        elements = sequence.split('|')
        # 중복을 제거하고 각 요소의 발생 빈도를 카운트
        unique_elements = set(elements)
        element_counter.update(unique_elements)
    
    # 오름차순으로 정렬하여 반환
    sorted_element_counts = sorted(element_counter.items(), key=lambda item: item[1])
    
    return sorted_element_counts


def main():
    # Create ArgumentParser object
    parser = argparse.ArgumentParser(
        description="A script to analyze common sequences among QUIC traffic. \nIt reads all .pcap files in a specified directory."
    )
    
    # Add an argument for the directory path
    parser.add_argument(
        'directory',
        type=str,
        help='The path to the directory containing .pcap files.'
    )
    
    # Parse the arguments passed from the command line
    args = parser.parse_args()

    # Call the function to read pcap files
    quic_message_all = analyze_pcap_files_in_directory(args.directory)
    # 요소 카운트 수행
    element_counts = count_unique_elements_in_sequences(quic_message_all)

    # 결과 출력
    for element, count in element_counts:
        print(f"{element}: {count}")

if __name__ == "__main__":
    main()